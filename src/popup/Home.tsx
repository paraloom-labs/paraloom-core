import { useState, useEffect, useRef } from "react"
import { createPortal } from "react-dom"
import { setLockState, updateAccounts, clearWallet, getNetwork, setNetwork as saveNetwork, getAutoLockMinutes, setAutoLockMinutes } from "~lib/storage/secure"
import { clearSession } from "~lib/storage/session"
import { getApprovedOrigins, removeApprovedOrigin } from "~lib/storage/connections"
import { useWalletStore } from "~lib/store/walletStore"
import { deriveKeypairFromSeed, decryptWallet, decryptSeedPhrase, deriveBoxKeypair, KDF_VERSION_SCRYPT } from "~lib/crypto/keyManagement"
import { getStoredWallet } from "~lib/storage/secure"
import type { Account } from "~lib/store/walletStore"
import { getConnection, deposit, getSolBalance, solanaAddress, solanaAddressToBytes } from "~lib/paraloom/bridge"
import { addNote, getNotes, markNoteSpent, shieldedBalance, shieldedTokenBalances, type ShieldedNote } from "~lib/paraloom/notes"

// Known shielded SPL tokens for display; unknown mints fall back to a truncated
// mint and raw base units.
const SHIELDED_TOKEN_META: Record<string, { symbol: string; decimals: number }> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: { symbol: "USDC", decimals: 6 }
}
import { withdraw } from "~lib/paraloom/withdraw"
import { transfer } from "~lib/paraloom/transfer"
import { depositV3, spendV3 } from "~lib/paraloom/transactFlow"
import { NATIVE_ASSET_HEX } from "~lib/prover"
import { addressBoxPubHex } from "~lib/crypto/keyManagement"
import { isValidShieldedAddress } from "~lib/crypto/addressChecksum"
import { scanForNotes } from "~lib/paraloom/scan"
import { dismissSwapOutput, listSwapOutputs, type SwapOutput } from "~lib/paraloom/swapOutputs"
import { recoverReshields } from "~lib/paraloom/reshieldRecovery"
import { reconcileSwapOutputs } from "~lib/paraloom/swapReconcile"
import { fetchPrices, SOL_MINT, type TokenPrice } from "~lib/paraloom/prices"
import { QRCodeSVG } from "qrcode.react"

import logoImg from "data-base64:~/../assets/icon.png"
import solanaLogo from "data-base64:~/../assets/solana.svg"
import usdcLogo from "data-base64:~/../assets/usdc.svg"

const AUTO_LOCK_OPTIONS: { value: number; label: string }[] = [
  { value: 5, label: "5 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "1 hour" },
  { value: 120, label: "2 hours" },
  { value: 240, label: "4 hours" }
]
const DEFAULT_AUTO_LOCK_MINUTES = 60

// Below this a native note costs more to withdraw (25 bps fee + tx fee) than it
// is worth: it is dust. Hidden from the withdraw selection so the picker isn't
// buried under worthless fillers, but still counted in the shielded total.
const WITHDRAW_DUST_LAMPORTS = 1_000_000n // 0.001 SOL

// Unspent native (non-token) notes worth withdrawing, largest first.
function spendableSolNotes(all: ShieldedNote[]): ShieldedNote[] {
  return all
    .filter(
      (n) =>
        !n.spent &&
        (!n.assetId || n.assetId === NATIVE_ASSET_HEX) &&
        BigInt(n.amount) >= WITHDRAW_DUST_LAMPORTS
    )
    .sort((a, b) => {
      const d = BigInt(b.amount) - BigInt(a.amount)
      return d > 0n ? 1 : d < 0n ? -1 : 0
    })
}

// Pick up to 2 spendable notes covering `lamports` (a transact spends 1–2 and
// returns change). Null if 2 notes can't cover it.
function selectSolWithdrawNotes(
  all: ShieldedNote[],
  lamports: bigint
): ShieldedNote[] | null {
  const sorted = spendableSolNotes(all)
  const chosen: ShieldedNote[] = []
  let sum = 0n
  for (const n of sorted) {
    chosen.push(n)
    sum += BigInt(n.amount)
    if (sum >= lamports) return chosen
    if (chosen.length === 2) break
  }
  return null
}

interface Token {
  symbol: string
  name: string
  balance: bigint
  usdValue: number
  decimals: number
  logo: string
}


interface HomeProps {
  onLock: () => void
}

// ─── Toast helper ───
function Toast({ message, type, onClose }: { message: string; type: "success" | "error" | "info"; onClose: () => void }) {
  return <div className={`toast ${type}`} onClick={onClose}>{message}</div>
}

export function Home({ onLock }: HomeProps) {
  const { wallet, balance, lock, seedPhrase, accounts, addAccount, switchAccount, currentAccountIndex, clear } = useWalletStore()
  const [bottomTab, setBottomTab] = useState<"home" | "activity" | "settings">("home")
  const [selectedToken, setSelectedToken] = useState<Token | null>(null)
  const [recipient, setRecipient] = useState("")
  const [amount, setAmount] = useState("")
  const [showSendModal, setShowSendModal] = useState(false)
  const [showReceiveModal, setShowReceiveModal] = useState(false)
  const [showAccountSwitcher, setShowAccountSwitcher] = useState(false)
  const [copied, setCopied] = useState(false)
  const [showAddAccount, setShowAddAccount] = useState(false)
  const [addAccountMethod, setAddAccountMethod] = useState<"create" | null>(null)
  const [accountName, setAccountName] = useState("")
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null)

  // Paraloom bridge state
  const [solBalance, setSolBalance] = useState(0n)
  const [shieldedLamports, setShieldedLamports] = useState(0n)
  const [shieldedTokens, setShieldedTokens] = useState<Record<string, bigint>>({})
  const [prices, setPrices] = useState<Record<string, TokenPrice>>({})
  const [showDepositModal, setShowDepositModal] = useState(false)
  const [depositAmount, setDepositAmount] = useState("")
  const [depositing, setDepositing] = useState(false)
  const [notes, setNotes] = useState<ShieldedNote[]>([])
  const [swapOutputs, setSwapOutputs] = useState<SwapOutput[]>([])
  // The activity row the user tapped, shown in an in-app detail sheet.
  const [activityDetail, setActivityDetail] = useState<{
    kind: "buy" | "deposit"
    pending: boolean
    amount: string
    sym: string
    address: string
    signature: string
    explorerUrl: string
    createdAt: number
  } | null>(null)
  const [showWithdrawModal, setShowWithdrawModal] = useState(false)
  const [withdrawAddress, setWithdrawAddress] = useState("")
  const [withdrawAmount, setWithdrawAmount] = useState("")
  const [withdrawing, setWithdrawing] = useState(false)
  const [showTransferModal, setShowTransferModal] = useState(false)
  const [transferAddress, setTransferAddress] = useState("")
  const [transferAmount, setTransferAmount] = useState("")
  const [transferring, setTransferring] = useState(false)

  // Settings state
  const [network, setNetworkState] = useState<"mainnet-beta" | "devnet">("mainnet-beta")
  const [autoLock, setAutoLock] = useState(DEFAULT_AUTO_LOCK_MINUTES)
  const [autoLockOpen, setAutoLockOpen] = useState(false)
  const [showPKModal, setShowPKModal] = useState(false)
  const [showSeedModal, setShowSeedModal] = useState(false)
  const [settingsPassword, setSettingsPassword] = useState("")
  const [settingsPasswordError, setSettingsPasswordError] = useState("")
  const [revealedPK, setRevealedPK] = useState<string | null>(null)
  const [pkVisible, setPkVisible] = useState(false)
  const [revealedSeed, setRevealedSeed] = useState<string | null>(null)
  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false)
  const [removeConfirmText, setRemoveConfirmText] = useState("")
  const [connectedSites, setConnectedSites] = useState<string[]>([])

  const autoLockRef = useRef<HTMLDivElement>(null)

  // Load settings on mount
  useEffect(() => {
    getNetwork().then(setNetworkState)
    getAutoLockMinutes().then(setAutoLock)
    getApprovedOrigins().then(setConnectedSites)
  }, [])

  // Load the private-swap outputs (tokens bought at fresh unlinkable addresses);
  // refresh when the Activity tab is opened.
  useEffect(() => {
    listSwapOutputs().then(setSwapOutputs).catch(() => {})
  }, [bottomTab])

  // Refresh the connected-sites list whenever the Settings tab is opened.
  useEffect(() => {
    if (bottomTab === "settings") {
      getApprovedOrigins().then(setConnectedSites)
    }
  }, [bottomTab])

  async function handleRevokeSite(origin: string) {
    await removeApprovedOrigin(origin)
    setConnectedSites((prev) => prev.filter((o) => o !== origin))
  }

  // Close the auto-lock dropdown when clicking outside of it
  useEffect(() => {
    if (!autoLockOpen) return
    function onClick(e: MouseEvent) {
      if (autoLockRef.current && !autoLockRef.current.contains(e.target as Node)) {
        setAutoLockOpen(false)
      }
    }
    document.addEventListener("mousedown", onClick)
    return () => document.removeEventListener("mousedown", onClick)
  }, [autoLockOpen])

  const tokens: Token[] = [
    {
      symbol: "SOL",
      name: "Solana",
      balance: solBalance,
      usdValue: 0,
      decimals: 9,
      logo: solanaLogo
    }
  ]

  const currentToken = selectedToken || tokens[0]

  function showToast(message: string, type: "success" | "error" | "info" = "info") {
    setToast({ message, type })
    setTimeout(() => setToast(null), 2500)
  }

  async function handleLock() {
    lock()
    await setLockState(true)
    await clearSession()
    onLock()
  }

  function handleCopyAddress() {
    if (wallet?.shieldedAddress) {
      navigator.clipboard.writeText(wallet.shieldedAddress)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  function formatBalance(balance: bigint, decimals: number): string {
    const units = Number(balance)
    const divisor = Math.pow(10, decimals)
    return (units / divisor).toFixed(4)
  }

  function timeAgo(ts: number): string {
    const s = Math.floor((Date.now() - ts) / 1000)
    if (s < 60) return "just now"
    const m = Math.floor(s / 60)
    if (m < 60) return `${m}m ago`
    const h = Math.floor(m / 60)
    if (h < 24) return `${h}h ago`
    const d = Math.floor(h / 24)
    if (d < 7) return `${d}d ago`
    return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" })
  }

  function shortSig(sig: string): string {
    return `${sig.slice(0, 4)}…${sig.slice(-4)}`
  }

  // Day bucket label for grouping the activity feed: Today / Yesterday / date.
  function dayLabel(ts: number): string {
    const d = new Date(ts)
    const now = new Date()
    const startOf = (x: Date) =>
      new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
    const days = Math.round((startOf(now) - startOf(d)) / 86_400_000)
    if (days <= 0) return "Today"
    if (days === 1) return "Yesterday"
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: d.getFullYear() === now.getFullYear() ? undefined : "numeric"
    })
  }

  function formatUSD(amount: number): string {
    return amount.toLocaleString('en-US', { style: 'currency', currency: 'USD' })
  }

  function getTotalPortfolioValue(): number {
    return tokens.reduce((total, token) => total + token.usdValue, 0)
  }

  function handleSend() {
    showToast("Paraloom Network is currently in development. Transfers will be enabled at mainnet launch.", "info")
    setShowSendModal(false)
    setRecipient("")
    setAmount("")
  }

  async function loadBalances() {
    if (!wallet) return
    try {
      const sol = await getSolBalance(getConnection(network), wallet.publicKey)
      setSolBalance(sol)
    } catch {
      // RPC unreachable — leave the last known balance in place
    }
    // Best-effort scan for received transfer notes (#196) before reading the
    // balance, so discovered notes are included. Swallowed if the transfer
    // node is unreachable — the shielded balance still reflects local notes.
    try {
      const boxSecret = deriveBoxKeypair(wallet.secretKey).secretKey
      await scanForNotes(
        wallet.shieldedAddress,
        boxSecret,
        Buffer.from(wallet.spendPrivkey).toString("hex")
      )
    } catch {
      // transfer node down / no scan endpoint — ignore
    }
    // Recover any re-shield whose deposit landed on-chain but whose note was
    // never persisted (or whose deposit never ran but the token is still at the
    // fresh address). Runs directly in the popup — no service-worker relay — so
    // it always fires when the wallet is opened, and the reads below then reflect
    // the recovered shielded balance.
    try {
      await recoverReshields(getConnection(network), wallet.shieldedAddress)
    } catch {
      // best-effort — the reads below still show whatever is already local
    }
    // Resolve stranded swap rows so Activity stops showing settled swaps as
    // "Pending" forever. Private swaps are mainnet-only, so this always runs
    // against the mainnet archival RPC regardless of the selected network. It
    // finishes a swap whose leg never ran and records one that already landed;
    // rows it cannot account for are left for the user to dismiss.
    try {
      const resolved = await reconcileSwapOutputs(
        getConnection("mainnet-beta"),
        wallet.shieldedAddress
      )
      if (resolved > 0) {
        listSwapOutputs().then(setSwapOutputs).catch(() => {})
      }
    } catch {
      // best-effort
    }
    try {
      setShieldedLamports(await shieldedBalance(wallet.shieldedAddress))
      setShieldedTokens(await shieldedTokenBalances(wallet.shieldedAddress))
      setNotes((await getNotes(wallet.shieldedAddress)).slice().reverse())
    } catch {
      // storage read failed — ignore
    }
  }

  useEffect(() => {
    loadBalances()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet, network])

  // Clear a stale "pending" swap row the reconciler could not account for. The
  // funds are already safe (re-shielded into the pool, or the input note was
  // never spent), so this only removes the misleading Activity entry.
  async function dismissActivity() {
    if (!activityDetail || activityDetail.kind !== "buy") return
    const addr = activityDetail.address
    await dismissSwapOutput(addr)
    setSwapOutputs((prev) => prev.filter((o) => o.freshAddress !== addr))
    setActivityDetail(null)
  }

  // USD prices for the held assets (SOL is always priced). Refetch when the set
  // of shielded tokens changes; a failed fetch just leaves amounts un-valued.
  // Note: fetchPrices restricts third-party queries to canonical public mints by default
  // to prevent leaking the user's private shielded holdings to Jupiter (#1577).
  useEffect(() => {
    let isMounted = true
    fetchPrices(Object.keys(shieldedTokens))
      .then((p) => {
        if (isMounted) setPrices(p)
      })
      .catch(() => {})
    return () => {
      isMounted = false
    }
  }, [shieldedTokens])

  async function handleDeposit() {
    if (!wallet) return
    const sol = Number(depositAmount)
    if (!sol || sol <= 0) {
      showToast("Enter a valid amount", "error")
      return
    }
    const lamports = BigInt(Math.round(sol * 1e9))
    if (lamports > solBalance) {
      showToast("Amount exceeds your SOL balance", "error")
      return
    }
    setDepositing(true)
    try {
      // Circuit v3 (#350): deposit_note appends the commitment to the
      // program's on-chain tree; depositV3 records the local note (with its
      // leaf index) itself.
      await depositV3(
        getConnection(network),
        wallet,
        wallet.shieldedAddress,
        Buffer.from(wallet.spendPrivkey).toString("hex"),
        lamports
      )
      setShowDepositModal(false)
      setDepositAmount("")
      await loadBalances()
    } catch (e) {
      showToast(`Deposit failed: ${e instanceof Error ? e.message : "error"}`, "error")
    } finally {
      setDepositing(false)
    }
  }

  async function handleWithdraw() {
    if (!wallet) return
    const target = withdrawAddress.trim() || solanaAddress(wallet.publicKey)
    let targetBytes: Uint8Array
    try {
      targetBytes = solanaAddressToBytes(target)
    } catch {
      showToast("Invalid Solana address", "error")
      return
    }
    const amt = Number(withdrawAmount)
    if (!amt || amt <= 0) {
      showToast("Enter an amount to withdraw", "error")
      return
    }
    const lamports = BigInt(Math.round(amt * 1e9))
    // Pick up to 2 spendable notes covering the amount; the wallet returns the
    // change as a new note, so the user withdraws a chosen amount instead of one
    // whole note. A single withdraw settles at most 2 notes.
    const inputs = selectSolWithdrawNotes(notes, lamports)
    if (!inputs) {
      const max = spendableSolNotes(notes)
        .slice(0, 2)
        .reduce((s, n) => s + BigInt(n.amount), 0n)
      showToast(
        `Max ${(Number(max) / 1e9).toFixed(4)} SOL per withdraw (2 notes); withdraw in parts`,
        "error"
      )
      return
    }
    setWithdrawing(true)
    try {
      const conn = getConnection(network)
      const before = await getSolBalance(conn, targetBytes)
      // Circuit v3 (#350): a withdraw is a transact with ext_amount < 0; the
      // proof binds the destination and the quorum settles it. spendV3 marks the
      // inputs spent and books any change note ONLY once settlement is confirmed
      // — the recipient balance rising above `before` — so a failed settlement
      // never hides still-spendable funds (paraloom-core#792).
      const { requestId, settled } = await spendV3(
        conn,
        wallet.shieldedAddress,
        Buffer.from(wallet.spendPrivkey).toString("hex"),
        addressBoxPubHex(wallet.shieldedAddress),
        inputs,
        lamports,
        { kind: "withdraw", recipientSolanaHex: Buffer.from(targetBytes).toString("hex") },
        {
          confirmSettled: async () => {
            for (let i = 0; i < 25; i++) {
              await new Promise((r) => setTimeout(r, 2000))
              if ((await getSolBalance(conn, targetBytes)) > before) return true
            }
            return false
          }
        }
      )
      if (settled) {
        showToast(`Withdrew ${amt.toFixed(4)} SOL to Solana`, "success")
        setShowWithdrawModal(false)
        setWithdrawAddress("")
        setWithdrawAmount("")
        await loadBalances()
      } else {
        showToast(`Submitted (${requestId.slice(0, 14)}…); settlement pending`, "info")
      }
    } catch (e) {
      showToast(`Withdraw failed: ${e instanceof Error ? e.message : "error"}`, "error")
    } finally {
      setWithdrawing(false)
    }
  }

  async function handleTransfer() {
    if (!wallet) return
    const to = transferAddress.trim()
    // A v2 shielded address is `paraloom1` + box(64 hex) + spend(64 hex) + an
    // 8-hex checksum. Validate the checksum, not just the length: without it a
    // length-preserving typo (one wrong character, or two swapped) would spend
    // into an address that decrypts to nothing spendable and strand the funds
    // with no recovery (paraloom-core#781, #770).
    if (!isValidShieldedAddress(to)) {
      showToast("Enter a valid paraloom1… shielded address", "error")
      return
    }
    if (to === wallet.shieldedAddress) {
      showToast("Cannot transfer to your own address", "error")
      return
    }
    const sol = parseFloat(transferAmount)
    if (!Number.isFinite(sol) || sol <= 0) {
      showToast("Enter a valid amount", "error")
      return
    }
    const amount = BigInt(Math.round(sol * 1e9))

    // Circuit v3 (#350): spend 1 or 2 notes; change comes back as a new note
    // (audit #16), so partial amounts work from a single note.
    const unspent = notes
      .filter((n) => !n.spent)
      .sort((a, b) => Number(BigInt(b.amount) - BigInt(a.amount)))
    const inputs: ShieldedNote[] = []
    let covered = 0n
    for (const n of unspent) {
      if (covered >= amount || inputs.length === 2) break
      inputs.push(n)
      covered += BigInt(n.amount)
    }
    if (covered < amount) {
      showToast("Your notes don't cover that amount", "error")
      return
    }

    setTransferring(true)
    try {
      // No external recipient balance to watch for a shielded transfer, so
      // spendV3 confirms settlement by watching the output commitment land in the
      // tree, and marks the inputs spent (and books change) only then — a failed
      // settlement leaves the notes spendable instead of hiding them
      // (paraloom-core#792).
      const { requestId, settled } = await spendV3(
        getConnection(network),
        wallet.shieldedAddress,
        Buffer.from(wallet.spendPrivkey).toString("hex"),
        addressBoxPubHex(wallet.shieldedAddress),
        inputs,
        amount,
        { kind: "transfer", recipientShielded: to }
      )
      if (settled) {
        showToast(`Transfer settled (${requestId.slice(0, 14)}…)`, "success")
      } else {
        showToast(
          `Submitted (${requestId.slice(0, 14)}…); settlement pending, notes stay spendable`,
          "info"
        )
      }
      setShowTransferModal(false)
      setTransferAddress("")
      setTransferAmount("")
      await loadBalances()
    } catch (e) {
      showToast(`Transfer failed: ${e instanceof Error ? e.message : "error"}`, "error")
    } finally {
      setTransferring(false)
    }
  }

  async function handleCreateAccount() {
    if (!seedPhrase) {
      showToast("No seed phrase available", "error")
      return
    }

    try {
      const newIndex = accounts.length
      const keypair = await deriveKeypairFromSeed(seedPhrase, newIndex)

      const newAccount: Account = {
        index: newIndex,
        name: accountName || `Account ${newIndex + 1}`,
        keypair,
        balance: 0n
      }

      addAccount(newAccount)

      const updatedAccounts = [...accounts, newAccount]
      await updateAccounts(updatedAccounts)

      switchAccount(newIndex)

      setShowAddAccount(false)
      setAddAccountMethod(null)
      setAccountName("")
      showToast(`${newAccount.name} created`, "success")
    } catch {
      showToast("Failed to create account", "error")
    }
  }

  async function handleNetworkChange(net: "mainnet-beta" | "devnet") {
    setNetworkState(net)
    await saveNetwork(net)
    showToast(net === "mainnet-beta" ? "Switched to Mainnet Beta" : "Switched to Devnet", "success")
  }

  async function handleAutoLockChange(minutes: number) {
    setAutoLock(minutes)
    setAutoLockOpen(false)
    await setAutoLockMinutes(minutes)
  }

  async function handleExportPK() {
    setSettingsPasswordError("")
    try {
      const stored = await getStoredWallet()
      if (!stored) throw new Error("No wallet found")
      const isLegacy = (stored.kdfVersion ?? 0) < KDF_VERSION_SCRYPT
      await decryptWallet(stored.encryptedData, settingsPassword, isLegacy)
      // Password correct — show the secret key as hex
      const hexKey = Buffer.from(wallet!.secretKey).toString("hex")
      setRevealedPK(hexKey)
      setPkVisible(false)
      setShowPKModal(false)
      setSettingsPassword("")
    } catch {
      setSettingsPasswordError("Incorrect password")
    }
  }

  async function handleShowSeed() {
    setSettingsPasswordError("")
    try {
      const stored = await getStoredWallet()
      if (!stored?.encryptedSeedPhrase) throw new Error("No seed phrase stored")
      const isLegacy = (stored.kdfVersion ?? 0) < KDF_VERSION_SCRYPT
      const phrase = decryptSeedPhrase(stored.encryptedSeedPhrase, settingsPassword, isLegacy)
      setRevealedSeed(phrase)
      setShowSeedModal(false)
      setSettingsPassword("")
    } catch {
      setSettingsPasswordError("Incorrect password")
    }
  }

  async function handleRemoveWallet() {
    if (removeConfirmText !== "DELETE") return
    await clearWallet()
    await clearSession()
    clear()
    onLock()
  }

  function resetSettingsModals() {
    setSettingsPassword("")
    setSettingsPasswordError("")
    setShowPKModal(false)
    setShowSeedModal(false)
    setRevealedPK(null)
    setPkVisible(false)
    setRevealedSeed(null)
    setShowRemoveConfirm(false)
    setRemoveConfirmText("")
  }

  if (!wallet) {
    return (
      <div className="container">
        <div className="error">No wallet loaded</div>
      </div>
    )
  }

  function shortenAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`
  }

  const currentAccount = accounts.find(acc => acc.index === currentAccountIndex) || accounts[0]
  const currentAccountName = currentAccount?.name || "Account 1"
  const currentAccountBadge = currentAccount ? `A${currentAccount.index + 1}` : "A1"

  return (
    <div className="wallet-layout">
      {/* Toast */}
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Compact Header */}
      <div className="wallet-header">
        <div className="header-content">
          <div className="account-switcher-trigger" onClick={() => setShowAccountSwitcher(!showAccountSwitcher)}>
            <div className="account-badge">{currentAccountBadge}</div>
            <div className="account-details">
              <div className="account-name">{currentAccountName}</div>
              <div className="account-address-short">
                {wallet?.shieldedAddress ? shortenAddress(wallet.shieldedAddress) : ''}
              </div>
            </div>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={`dropdown-icon ${showAccountSwitcher ? 'open' : ''}`}>
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </div>
          <div className="header-actions">
            <button className="header-btn" onClick={handleCopyAddress} title={copied ? "Copied!" : "Copy address"}>
              {copied ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              )}
            </button>
            <button className="header-btn" onClick={handleLock} title="Lock">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </button>
          </div>
        </div>

        {/* Account Switcher Dropdown */}
        {showAccountSwitcher && (
          <div className="account-dropdown">
            <div className="account-dropdown-header">
              <span>My Accounts</span>
              <button className="close-dropdown" onClick={() => setShowAccountSwitcher(false)}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
            <div className="account-list">
              {accounts.map((account) => (
                <div
                  key={account.index}
                  className={`account-item ${account.index === currentAccountIndex ? 'active' : ''}`}
                  onClick={() => {
                    if (account.index !== currentAccountIndex) {
                      switchAccount(account.index)
                    }
                    setShowAccountSwitcher(false)
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="account-item-badge">A{account.index + 1}</div>
                  <div className="account-item-info">
                    <div className="account-item-name">{account.name}</div>
                    <div className="account-item-balance">{shortenAddress(account.keypair.shieldedAddress)}</div>
                  </div>
                  {account.index === currentAccountIndex && (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="check-icon">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                  )}
                </div>
              ))}
              <button className="add-account-item" onClick={() => {
                setShowAccountSwitcher(false)
                setShowAddAccount(true)
              }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="12" y1="5" x2="12" y2="19"></line>
                  <line x1="5" y1="12" x2="19" y2="12"></line>
                </svg>
                <span>Add Account</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="wallet-content">
        {bottomTab === "home" ? (
          <>
            {(() => {
              const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
              type Holding = {
                key: string
                name: string
                symbol: string
                usdcMark?: boolean
                amount: bigint
                decimals: number
                mint: string
                privacy: "public" | "shielded"
              }
              const holdings: Holding[] = []
              if (solBalance > 0n)
                holdings.push({ key: "pub-sol", name: "Solana", symbol: "SOL", amount: solBalance, decimals: 9, mint: SOL_MINT, privacy: "public" })
              if (shieldedLamports > 0n)
                holdings.push({ key: "sh-sol", name: "Solana", symbol: "SOL", amount: shieldedLamports, decimals: 9, mint: SOL_MINT, privacy: "shielded" })
              for (const [mint, amount] of Object.entries(shieldedTokens)) {
                if (amount <= 0n) continue
                const meta = SHIELDED_TOKEN_META[mint]
                holdings.push({
                  key: `sh-${mint}`,
                  name: meta?.symbol === "USDC" ? "USD Coin" : (meta?.symbol ?? "Token"),
                  symbol: meta?.symbol ?? `${mint.slice(0, 4)}…`,
                  usdcMark: mint === USDC_MINT,
                  amount,
                  decimals: meta?.decimals ?? 0,
                  mint,
                  privacy: "shielded"
                })
              }
              const usdOf = (h: Holding): number | null => {
                const p = prices[h.mint]?.usdPrice
                return p != null ? (Number(h.amount) / 10 ** h.decimals) * p : null
              }
              const total = holdings.reduce((s, h) => s + (usdOf(h) ?? 0), 0)
              const shieldedUsd = holdings
                .filter((h) => h.privacy === "shielded")
                .reduce((s, h) => s + (usdOf(h) ?? 0), 0)
              const publicUsd = total - shieldedUsd
              const fmtUsd = (n: number) =>
                `$${n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
              const eye = (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"></path>
                </svg>
              )
              const shield = (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
              )
              return (
                <>
                  <div className="home-total-label">Total balance</div>
                  <div className="home-total">{fmtUsd(total)}</div>
                  <div className="home-split">
                    <span className="home-chip">{eye}{fmtUsd(publicUsd)} public</span>
                    <span className="home-chip sh">{shield}{fmtUsd(shieldedUsd)} shielded</span>
                  </div>

                  <div className="home-actions">
                    <button className="home-act" onClick={() => setShowReceiveModal(true)}>
                      <span className="home-act-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg></span>
                      <span className="home-act-lb">Receive</span>
                    </button>
                    <button className="home-act" onClick={() => { setShowDepositModal(true); loadBalances() }}>
                      <span className="home-act-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v13"></path><polyline points="6 9 12 15 18 9"></polyline><line x1="5" y1="21" x2="19" y2="21"></line></svg></span>
                      <span className="home-act-lb">Deposit</span>
                    </button>
                    <button className="home-act" onClick={() => { if (wallet) setWithdrawAddress(solanaAddress(wallet.publicKey)); setShowWithdrawModal(true); loadBalances() }}>
                      <span className="home-act-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22V9"></path><polyline points="6 15 12 9 18 15"></polyline><line x1="5" y1="3" x2="19" y2="3"></line></svg></span>
                      <span className="home-act-lb">Withdraw</span>
                    </button>
                    <button className="home-act" onClick={() => { setShowTransferModal(true); loadBalances() }}>
                      <span className="home-act-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="4" y1="9" x2="20" y2="9"></line><polyline points="15 4 20 9 15 14"></polyline><line x1="20" y1="15" x2="4" y2="15"></line><polyline points="9 10 4 15 9 20"></polyline></svg></span>
                      <span className="home-act-lb">Transfer</span>
                    </button>
                  </div>

                  <div className="home-assets-head"><h3>Assets</h3></div>
                  <div className="home-assets">
                    {holdings.length === 0 ? (
                      <div className="home-assets-empty">No assets yet. Deposit SOL to get started.</div>
                    ) : (
                      holdings.map((h) => {
                        const usd = usdOf(h)
                        const chg = prices[h.mint]?.priceChange24h
                        return (
                          <div className="home-asset" key={h.key}>
                            <div className={`home-asset-logo ${h.usdcMark ? "usdc" : "sol"}`}>
                              <img src={h.usdcMark ? usdcLogo : solanaLogo} alt="" />
                            </div>
                            <div className="home-asset-info">
                              <div className="home-asset-row">
                                <span className="home-asset-name">
                                  {h.name}
                                  <span className={`home-tag ${h.privacy === "shielded" ? "sh" : ""}`}>
                                    {h.privacy}
                                  </span>
                                </span>
                                <span className="home-asset-amt">
                                  {formatBalance(h.amount, h.decimals)} {h.symbol}
                                </span>
                              </div>
                              <div className="home-asset-row">
                                <span className="home-asset-sub">
                                  {h.privacy === "shielded" ? "Private · unlinkable" : "Solana"}
                                </span>
                                <span className="home-asset-val">
                                  {usd != null ? fmtUsd(usd) : "—"}
                                  {usd != null && chg != null && chg !== 0 && (
                                    <em className={chg >= 0 ? "up" : "down"}>
                                      {" "}
                                      {chg >= 0 ? "+" : ""}
                                      {chg.toFixed(2)}%
                                    </em>
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        )
                      })
                    )}
                  </div>
                </>
              )
            })()}
          </>
        ) : bottomTab === "activity" ? (
          <div className="activity-content">
            {(() => {
              // Only real deposits belong in the feed. The zero-value change/
              // filler notes a transact emits carry an empty signature, so
              // rendering them all under key="" collided React keys.
              const deposits = notes.filter(
                (n) => n.source === "deposit" && Number(n.amount) > 0
              )
              const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
              // Wrapped-SOL mint: the swaps app sends this as the outputMint for a
              // SOL output, so a token->SOL buy must be shown (and scaled) as SOL.
              const WSOL_MINT = "So11111111111111111111111111111111111111112"

              if (deposits.length === 0 && swapOutputs.length === 0) {
                return (
                  <div className="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                      <polyline points="14 2 14 8 20 8"></polyline>
                      <line x1="16" y1="13" x2="8" y2="13"></line>
                      <line x1="16" y1="17" x2="8" y2="17"></line>
                      <polyline points="10 9 9 9 8 9"></polyline>
                    </svg>
                    <div className="empty-title">No Activity Yet</div>
                    <div className="empty-subtitle">Your transaction history will appear here</div>
                  </div>
                )
              }

              // Unify buys + deposits into one time-ordered feed, then bucket by
              // day so the list reads like a real transaction history.
              type Entry =
                | { kind: "buy"; ts: number; s: SwapOutput }
                | { kind: "deposit"; ts: number; n: ShieldedNote }
              const entries: Entry[] = [
                ...swapOutputs.map((s) => ({ kind: "buy" as const, ts: s.createdAt, s })),
                ...deposits.map((n) => ({ kind: "deposit" as const, ts: n.createdAt, n }))
              ].sort((a, b) => b.ts - a.ts)

              const groups: { label: string; items: Entry[] }[] = []
              for (const e of entries) {
                const label = dayLabel(e.ts)
                const last = groups[groups.length - 1]
                if (last && last.label === label) last.items.push(e)
                else groups.push({ label, items: [e] })
              }

              return (
                <div className="activity-feed">
                  {groups.map((g) => (
                    <div className="activity-group" key={g.label}>
                      <div className="activity-day">{g.label}</div>
                      <div className="activity-list">
                        {g.items.map((e, i) => {
                          if (e.kind === "buy") {
                            const s = e.s
                            const done = s.outAmount > 0 && !!s.swapSignature
                            const isSolOut =
                              s.outputMint === "SOL" || s.outputMint === WSOL_MINT
                            const sym = isSolOut
                              ? "SOL"
                              : s.outputMint === USDC_MINT
                                ? "USDC"
                                : "token"
                            const outDiv = isSolOut ? 1e9 : 1e6
                            return (
                              <div
                                key={s.freshAddress || `buy-${i}`}
                                className="activity-item"
                                role="button"
                                tabIndex={0}
                                onClick={() =>
                                  setActivityDetail({
                                    kind: "buy",
                                    pending: !done,
                                    amount: done
                                      ? `+${(s.outAmount / outDiv).toFixed(4)} ${sym}`
                                      : "",
                                    sym,
                                    address: s.freshAddress,
                                    signature: s.swapSignature || "",
                                    explorerUrl: `https://solscan.io/account/${s.freshAddress}`,
                                    createdAt: s.createdAt
                                  })
                                }
                              >
                                <div className="activity-avatar buy">
                                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                                    <polyline points="17 1 21 5 17 9"></polyline>
                                    <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                                    <polyline points="7 23 3 19 7 15"></polyline>
                                    <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                                  </svg>
                                  <span className={`activity-badge ${done ? "ok" : "pending"}`}>
                                    {done ? (
                                      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                                        <polyline points="20 6 9 17 4 12"></polyline>
                                      </svg>
                                    ) : (
                                      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                        <circle cx="12" cy="12" r="9"></circle>
                                        <polyline points="12 7 12 12 16 14"></polyline>
                                      </svg>
                                    )}
                                  </span>
                                </div>
                                <div className="activity-info">
                                  <div className="activity-row">
                                    <span className="activity-title">Private buy</span>
                                    {done ? (
                                      <span className="activity-amount pos">
                                        +{(s.outAmount / outDiv).toFixed(4)} {sym}
                                      </span>
                                    ) : (
                                      <span className="activity-pill">Pending</span>
                                    )}
                                  </div>
                                  <div className="activity-row">
                                    <span className="activity-sub">
                                      {done ? sym : "settling"}
                                      <span className="activity-dot">·</span>
                                      {s.freshAddress.slice(0, 4)}…{s.freshAddress.slice(-4)}
                                    </span>
                                    <span className="activity-time">{timeAgo(s.createdAt)}</span>
                                  </div>
                                </div>
                              </div>
                            )
                          }
                          const n = e.n
                          // A re-shielded SPL note carries a mint; render it with
                          // the token's decimals/symbol, not the SOL divisor.
                          const USDC_MINT_DEP =
                            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
                          const depSym =
                            n.mint === USDC_MINT_DEP ? "USDC" : n.mint ? "token" : "SOL"
                          const depAmount =
                            n.mint === USDC_MINT_DEP
                              ? (Number(n.amount) / 1e6).toFixed(4)
                              : n.mint
                                ? n.amount
                                : (Number(n.amount) / 1e9).toFixed(4)
                          return (
                            <div
                              key={n.signature || n.commitment || `dep-${i}`}
                              className="activity-item"
                              role="button"
                              tabIndex={0}
                              onClick={() =>
                                setActivityDetail({
                                  kind: "deposit",
                                  pending: false,
                                  amount: `+${depAmount} ${depSym}`,
                                  sym: depSym,
                                  address: "",
                                  signature: n.signature,
                                  explorerUrl: `https://explorer.solana.com/tx/${n.signature}?cluster=${network}`,
                                  createdAt: n.createdAt
                                })
                              }
                            >
                              <div className="activity-avatar deposit">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                                  <path d="M12 3v13"></path>
                                  <polyline points="6 10 12 16 18 10"></polyline>
                                  <line x1="5" y1="21" x2="19" y2="21"></line>
                                </svg>
                                <span className="activity-badge ok">
                                  <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                                    <polyline points="20 6 9 17 4 12"></polyline>
                                  </svg>
                                </span>
                              </div>
                              <div className="activity-info">
                                <div className="activity-row">
                                  <span className="activity-title">Deposit</span>
                                  <span className="activity-amount pos">
                                    +{depAmount} {depSym}
                                  </span>
                                </div>
                                <div className="activity-row">
                                  <span className="activity-sub">
                                    Shielded
                                    <span className="activity-dot">·</span>
                                    {shortSig(n.signature)}
                                  </span>
                                  <span className="activity-time">{timeAgo(n.createdAt)}</span>
                                </div>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )
            })()}

            {activityDetail &&
              createPortal(
                <div className="detail-overlay" onClick={() => setActivityDetail(null)}>
                <div className="detail-sheet" onClick={(e) => e.stopPropagation()}>
                  <div className={`detail-title ${activityDetail.pending ? "muted" : ""}`}>
                    {activityDetail.kind === "buy" ? "Private buy" : "Deposit"}
                  </div>
                  <div className={`detail-hero-icon ${activityDetail.kind}`}>
                    {activityDetail.kind === "buy" ? (
                      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                        <polyline points="17 1 21 5 17 9"></polyline>
                        <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                        <polyline points="7 23 3 19 7 15"></polyline>
                        <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                      </svg>
                    ) : (
                      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                        <path d="M12 3v13"></path>
                        <polyline points="6 10 12 16 18 10"></polyline>
                        <line x1="5" y1="21" x2="19" y2="21"></line>
                      </svg>
                    )}
                    <span className={`activity-badge ${activityDetail.pending ? "pending" : "ok"}`}>
                      {activityDetail.pending ? (
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                          <circle cx="12" cy="12" r="9"></circle>
                          <polyline points="12 7 12 12 16 14"></polyline>
                        </svg>
                      ) : (
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      )}
                    </span>
                  </div>
                  <div className={`detail-amount ${activityDetail.pending ? "muted" : "pos"}`}>
                    {activityDetail.pending ? "Pending" : activityDetail.amount}
                  </div>

                  <div className="detail-rows">
                    <div className="detail-row">
                      <span className="detail-key">Date</span>
                      <span className="detail-val">
                        {new Date(activityDetail.createdAt).toLocaleString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                          hour: "numeric",
                          minute: "2-digit"
                        })}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-key">Status</span>
                      <span className={`detail-val ${activityDetail.pending ? "warn" : "good"}`}>
                        {activityDetail.pending ? "Settling" : "Succeeded"}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-key">Type</span>
                      <span className="detail-val">
                        {activityDetail.kind === "buy"
                          ? `Private swap → ${activityDetail.sym}`
                          : "Shielded deposit"}
                      </span>
                    </div>
                    {activityDetail.kind === "buy" && (
                      <div className="detail-row">
                        <span className="detail-key">Fresh address</span>
                        <span className="detail-val mono">
                          {activityDetail.address.slice(0, 4)}…{activityDetail.address.slice(-4)}
                        </span>
                      </div>
                    )}
                    {activityDetail.signature && (
                      <div className="detail-row">
                        <span className="detail-key">Signature</span>
                        <span className="detail-val mono">{shortSig(activityDetail.signature)}</span>
                      </div>
                    )}
                    <div className="detail-row">
                      <span className="detail-key">Network</span>
                      <span className="detail-val">
                        Solana {network === "mainnet-beta" ? "Mainnet" : "Devnet"}
                      </span>
                    </div>
                  </div>

                  {activityDetail.kind === "buy" && activityDetail.pending && (
                    <p className="detail-note">
                      Still pending after a while? Your funds are safe in your shielded
                      balance. Dismissing only clears this row.
                    </p>
                  )}

                  <div className="detail-actions">
                    <a
                      className="detail-btn ghost"
                      href={activityDetail.explorerUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      View on {activityDetail.kind === "buy" ? "Solscan" : "Explorer"}
                    </a>
                    {activityDetail.kind === "buy" && activityDetail.pending ? (
                      <button className="detail-btn danger" onClick={dismissActivity}>
                        Dismiss
                      </button>
                    ) : (
                      <button className="detail-btn" onClick={() => setActivityDetail(null)}>
                        Close
                      </button>
                    )}
                  </div>
                </div>
              </div>,
                document.body
              )}
          </div>
        ) : (
          /* ─── Settings Tab ─── */
          <div className="settings-content">
            {/* Network Selection */}
            <div className="settings-section">
              <div className="settings-section-title">Network</div>
              <div className="network-options">
                <div
                  className={`network-option ${network === "mainnet-beta" ? "active" : ""}`}
                  onClick={() => handleNetworkChange("mainnet-beta")}
                >
                  <div className="network-dot" />
                  <div className="network-info">
                    <div className="network-name">Mainnet Beta</div>
                    <div className="network-url">node.paraloom.io</div>
                  </div>
                </div>
                <div
                  className={`network-option ${network === "devnet" ? "active" : ""}`}
                  onClick={() => handleNetworkChange("devnet")}
                >
                  <div className="network-dot" />
                  <div className="network-info">
                    <div className="network-name">Devnet</div>
                    <div className="network-url">api.devnet.solana.com</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Security Section */}
            <div className="settings-section">
              <div className="settings-section-title">Security</div>

              {/* Private Key Export */}
              {!revealedPK ? (
                <div
                  className="settings-item"
                  onClick={() => { setShowPKModal(true); setSettingsPassword(""); setSettingsPasswordError(""); }}
                >
                  <div className="settings-item-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                    </svg>
                  </div>
                  <div className="settings-item-info">
                    <div className="settings-item-label">Export Private Key</div>
                    <div className="settings-item-desc">View your private key</div>
                  </div>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="settings-item-arrow">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </div>
              ) : (
                <div className="pk-reveal">
                  <div className="pk-warning">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Never share your private key with anyone
                  </div>
                  <div className="pk-reveal-box">
                    <div className={`pk-reveal-text ${!pkVisible ? "masked" : ""}`}>
                      {revealedPK}
                    </div>
                  </div>
                  <div className="pk-reveal-actions">
                    <button onClick={() => setPkVisible(!pkVisible)}>
                      {pkVisible ? (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </svg>
                      ) : (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </svg>
                      )}
                      {pkVisible ? "Hide" : "Reveal"}
                    </button>
                    <button onClick={() => {
                      navigator.clipboard.writeText(revealedPK)
                      showToast("Private key copied!", "success")
                    }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                      Copy
                    </button>
                    <button onClick={() => { setRevealedPK(null); setPkVisible(false); }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                      Close
                    </button>
                  </div>
                </div>
              )}

              {/* Seed Phrase */}
              {!revealedSeed ? (
                <div
                  className="settings-item"
                  onClick={() => { setShowSeedModal(true); setSettingsPassword(""); setSettingsPasswordError(""); }}
                >
                  <div className="settings-item-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                  </div>
                  <div className="settings-item-info">
                    <div className="settings-item-label">Show Recovery Phrase</div>
                    <div className="settings-item-desc">View your 12-word seed phrase</div>
                  </div>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="settings-item-arrow">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </div>
              ) : (
                <div className="pk-reveal">
                  <div className="pk-warning">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    Never share your recovery phrase with anyone
                  </div>
                  <div className="seed-reveal-grid">
                    {revealedSeed.split(" ").map((word, i) => (
                      <div key={i} className="seed-word">
                        <span className="seed-index">{i + 1}</span>
                        <span className="seed-text">{word}</span>
                      </div>
                    ))}
                  </div>
                  <div className="pk-reveal-actions">
                    <button onClick={() => {
                      navigator.clipboard.writeText(revealedSeed)
                      showToast("Recovery phrase copied!", "success")
                    }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                      Copy
                    </button>
                    <button onClick={() => setRevealedSeed(null)}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                      Close
                    </button>
                  </div>
                </div>
              )}

              {/* Auto-lock Timeout */}
              <div className="settings-item" style={{ cursor: "default" }}>
                <div className="settings-item-icon">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <polyline points="12 6 12 12 16 14" />
                  </svg>
                </div>
                <div className="settings-item-info">
                  <div className="settings-item-label">Auto-lock</div>
                </div>
                <div className="autolock-dropdown" ref={autoLockRef}>
                  <button
                    type="button"
                    className={`autolock-trigger ${autoLockOpen ? "open" : ""}`}
                    onClick={() => setAutoLockOpen((v) => !v)}
                  >
                    <span>{AUTO_LOCK_OPTIONS.find((o) => o.value === autoLock)?.label ?? `${autoLock} minutes`}</span>
                    <svg className="autolock-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="6 9 12 15 18 9" />
                    </svg>
                  </button>
                  {autoLockOpen && (
                    <div className="autolock-menu">
                      {AUTO_LOCK_OPTIONS.map((opt) => (
                        <button
                          key={opt.value}
                          type="button"
                          className={`autolock-menu-item ${opt.value === autoLock ? "active" : ""}`}
                          onClick={() => handleAutoLockChange(opt.value)}
                        >
                          <span>{opt.label}</span>
                          {opt.value === autoLock && (
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                              <polyline points="20 6 9 17 4 12" />
                            </svg>
                          )}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Connected Sites */}
            <div className="settings-section">
              <div className="settings-section-title">Connected Sites</div>
              {connectedSites.length === 0 ? (
                <div className="connected-empty">No sites connected yet.</div>
              ) : (
                <div className="connected-list">
                  {connectedSites.map((origin) => {
                    let host = origin
                    try {
                      host = new URL(origin).host
                    } catch {}
                    return (
                      <div key={origin} className="connected-row">
                        <div className="connected-dot" />
                        <span className="connected-host">{host}</span>
                        <button
                          type="button"
                          className="connected-revoke"
                          onClick={() => handleRevokeSite(origin)}
                        >
                          Disconnect
                        </button>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Danger Zone */}
            <div className="danger-zone">
              <div className="settings-section-title" style={{ marginBottom: 10 }}>Danger Zone</div>
              {!showRemoveConfirm ? (
                <button className="danger-btn" onClick={() => setShowRemoveConfirm(true)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="3 6 5 6 21 6" />
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                  </svg>
                  Remove Wallet
                </button>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <div className="pk-warning">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    This will permanently delete your wallet. Make sure you have backed up your recovery phrase.
                  </div>
                  <input
                    type="text"
                    className="danger-confirm-input"
                    placeholder='Type "DELETE" to confirm'
                    value={removeConfirmText}
                    onChange={(e) => setRemoveConfirmText(e.target.value)}
                  />
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    <button
                      className="button button-secondary"
                      style={{ fontSize: 12, padding: "10px 14px" }}
                      onClick={() => { setShowRemoveConfirm(false); setRemoveConfirmText(""); }}
                    >
                      Cancel
                    </button>
                    <button
                      className="danger-btn"
                      style={{ opacity: removeConfirmText === "DELETE" ? 1 : 0.4, cursor: removeConfirmText === "DELETE" ? "pointer" : "not-allowed" }}
                      onClick={handleRemoveWallet}
                    >
                      Delete Wallet
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Add Account Modal */}
      {showAddAccount && (
        <div className="modal-overlay" onClick={() => {
          setShowAddAccount(false)
          setAddAccountMethod(null)
        }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Add Account</h2>
              <button className="modal-close" onClick={() => {
                setShowAddAccount(false)
                setAddAccountMethod(null)
              }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            {!addAccountMethod ? (
              <div className="add-account-options">
                <button className="add-account-option" onClick={() => setAddAccountMethod("create")}>
                  <div className="option-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"></circle>
                      <line x1="12" y1="8" x2="12" y2="16"></line>
                      <line x1="8" y1="12" x2="16" y2="12"></line>
                    </svg>
                  </div>
                  <div className="option-info">
                    <div className="option-title">Create New Account</div>
                    <div className="option-description">Generate from existing wallet</div>
                  </div>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="option-arrow">
                    <polyline points="9 18 15 12 9 6"></polyline>
                  </svg>
                </button>

              </div>
            ) : (
              <div className="add-account-form">
                <div className="form-info-compact">
                  <p className="form-message">A new account will be generated from your existing wallet using a different derivation path.</p>
                </div>
                <div className="input-group">
                  <label className="label">Account Name (Optional)</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g., Trading Account, Savings..."
                    value={accountName}
                    onChange={(e) => setAccountName(e.target.value)}
                  />
                  <span className="input-hint">Default: Account {accounts.length + 1}</span>
                </div>
                <div className="form-actions">
                  <button className="button button-secondary" onClick={() => {
                    setAddAccountMethod(null)
                    setAccountName("")
                  }}>
                    Back
                  </button>
                  <button className="button" onClick={handleCreateAccount}>Create Account</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Bottom Navigation */}
      <div className="bottom-nav">
        <button
          className={`nav-item ${bottomTab === "home" ? "active" : ""}`}
          onClick={() => { setBottomTab("home"); resetSettingsModals(); }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
            <polyline points="9 22 9 12 15 12 15 22"></polyline>
          </svg>
          <div className="nav-label">Home</div>
        </button>
        <button
          className={`nav-item ${bottomTab === "activity" ? "active" : ""}`}
          onClick={() => { setBottomTab("activity"); resetSettingsModals(); }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
          <div className="nav-label">Activity</div>
        </button>
        <button
          className={`nav-item ${bottomTab === "settings" ? "active" : ""}`}
          onClick={() => setBottomTab("settings")}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          <div className="nav-label">Settings</div>
        </button>
      </div>

      {/* Receive Modal */}
      {showReceiveModal && (
        <div className="modal-overlay" onClick={() => setShowReceiveModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <div className="modal-token-icon">
                  <img src={currentToken.logo} alt={currentToken.symbol} className="modal-token-img" />
                </div>
                <div>
                  <h3>Receive {currentToken.symbol}</h3>
                  <span className="modal-token-name">{currentToken.name}</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowReceiveModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="receive-body">
              <div className="qr-code-wrapper">
                <QRCodeSVG
                  value={wallet.shieldedAddress}
                  size={180}
                  bgColor="#0D0D14"
                  fgColor="#D4A017"
                  level="H"
                  includeMargin={true}
                  imageSettings={{
                    src: logoImg,
                    x: undefined,
                    y: undefined,
                    height: 36,
                    width: 36,
                    excavate: true,
                  }}
                />
              </div>

              <div className="receive-address-section">
                <div className="receive-address-label">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                  Your Shielded Address
                </div>
                <div className="receive-address-box">
                  <code>{wallet.shieldedAddress}</code>
                </div>
              </div>

              <div className="receive-actions">
                <button className="button copy-button" onClick={handleCopyAddress}>
                  {copied ? (
                    <>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                      Copied!
                    </>
                  ) : (
                    <>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                      Copy Address
                    </>
                  )}
                </button>
              </div>

              <div className="receive-note">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="16" x2="12" y2="12" />
                  <line x1="12" y1="8" x2="12.01" y2="8" />
                </svg>
                All tokens use the same shielded address
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Withdraw Modal */}
      {showWithdrawModal && (
        <div className="modal-overlay" onClick={() => !withdrawing && setShowWithdrawModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <div>
                  <h3>Withdraw to Solana</h3>
                  <span className="modal-token-name">Move shielded SOL back to a Solana address</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => !withdrawing && setShowWithdrawModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="send-form">
              <div className="form-group">
                <label className="form-label">Destination Solana address</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Solana address"
                  value={withdrawAddress}
                  onChange={(e) => setWithdrawAddress(e.target.value)}
                />
                <div className="balance-info">Prefilled with your address — edit to send elsewhere</div>
              </div>

              {(() => {
                const spend = spendableSolNotes(notes)
                const spendSum = spend.reduce((s, n) => s + BigInt(n.amount), 0n)
                const maxOne = spend.slice(0, 2).reduce((s, n) => s + BigInt(n.amount), 0n)
                const allSol = notes.filter(
                  (n) => !n.spent && (!n.assetId || n.assetId === NATIVE_ASSET_HEX)
                )
                const dustCount = allSol.length - spend.length
                const dustSum =
                  allSol.reduce((s, n) => s + BigInt(n.amount), 0n) - spendSum
                return (
                  <div className="form-group">
                    <label className="form-label">
                      Amount to withdraw
                      {maxOne > 0n && (
                        <button
                          type="button"
                          className="label-max"
                          onClick={() => setWithdrawAmount(String(Number(maxOne) / 1e9))}
                        >
                          Max {(Number(maxOne) / 1e9).toFixed(4)} SOL
                        </button>
                      )}
                    </label>
                    <input
                      type="number"
                      className="form-input"
                      placeholder="0.0"
                      value={withdrawAmount}
                      onChange={(e) => setWithdrawAmount(e.target.value)}
                    />
                    <div className="balance-info">
                      {spend.length === 0
                        ? "No spendable notes — deposit first"
                        : `Up to ${(Number(maxOne) / 1e9).toFixed(4)} SOL per withdraw (2 notes at a time)`}
                      {dustCount > 0 &&
                        ` · ${(Number(dustSum) / 1e9).toFixed(4)} SOL in ${dustCount} dust note(s) hidden`}
                    </div>
                  </div>
                )
              })()}

              <button
                className="button send-button"
                disabled={
                  withdrawing ||
                  !withdrawAddress.trim() ||
                  !withdrawAmount ||
                  Number(withdrawAmount) <= 0 ||
                  spendableSolNotes(notes).length === 0
                }
                onClick={handleWithdraw}
              >
                {withdrawing ? "Proving & settling…" : "Withdraw"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Transfer Modal (shielded → shielded, #197) */}
      {showTransferModal && (
        <div className="modal-overlay" onClick={() => !transferring && setShowTransferModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <div>
                  <h3>Shielded transfer</h3>
                  <span className="modal-token-name">Send shielded SOL privately to another paraloom address</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => !transferring && setShowTransferModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="send-form">
              <div className="form-group">
                <label className="form-label">Recipient shielded address</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="paraloom1…"
                  value={transferAddress}
                  onChange={(e) => setTransferAddress(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Amount (SOL)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="0.0"
                  value={transferAmount}
                  onChange={(e) => setTransferAmount(e.target.value)}
                />
                <div className="balance-info">
                  Spends your 2 largest notes; the remainder returns as change. Shielded total:{" "}
                  {(Number(shieldedLamports) / 1e9).toFixed(4)} SOL across{" "}
                  {notes.filter((n) => !n.spent).length} note(s)
                </div>
              </div>

              <button
                className="button send-button"
                disabled={transferring || !transferAddress.trim() || !transferAmount.trim() || notes.filter((n) => !n.spent).length < 2}
                onClick={handleTransfer}
              >
                {transferring ? "Proving & sending…" : "Send shielded transfer"}
              </button>
              {notes.filter((n) => !n.spent).length < 2 && (
                <div className="balance-info">Needs at least 2 unspent notes (deposit again to split).</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Deposit Modal */}
      {showDepositModal && (
        <div className="modal-overlay" onClick={() => setShowDepositModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <div>
                  <h3>Deposit to Paraloom</h3>
                  <span className="modal-token-name">Move public SOL into your shielded balance</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowDepositModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="send-form">
              <div className="form-group">
                <label className="form-label">Amount</label>
                <div className="amount-input-wrapper">
                  <input
                    type="number"
                    className="form-input amount-input"
                    placeholder="0.0000"
                    value={depositAmount}
                    onChange={(e) => setDepositAmount(e.target.value)}
                  />
                  <div className="input-suffix">SOL</div>
                </div>
                <div className="balance-info">
                  Available: {(Number(solBalance) / 1e9).toFixed(4)} SOL
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Funded from your Solana address</label>
                <div className="receive-address-box">
                  <code>{wallet ? solanaAddress(wallet.publicKey) : ""}</code>
                </div>
              </div>

              <div className="send-fee-row">
                <span className="fee-label">Network</span>
                <span className="fee-value">{network}</span>
              </div>

              <button
                className="button send-button"
                disabled={!depositAmount || depositing}
                onClick={handleDeposit}
              >
                {depositing ? "Depositing…" : "Deposit"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Send Modal */}
      {showSendModal && (
        <div className="modal-overlay" onClick={() => setShowSendModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-header-left">
                <div className="modal-token-icon">
                  <img src={currentToken.logo} alt={currentToken.symbol} className="modal-token-img" />
                </div>
                <div>
                  <h3>Send {currentToken.symbol}</h3>
                  <span className="modal-token-name">{currentToken.name}</span>
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowSendModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="send-form">
              <div className="form-group">
                <label className="form-label">Recipient</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="paraloom1..."
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Amount</label>
                <div className="amount-input-wrapper">
                  <input
                    type="number"
                    className="form-input amount-input"
                    placeholder="0.0000"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                  />
                  <div className="input-suffix">{currentToken.symbol}</div>
                  <button
                    type="button"
                    className="max-button"
                    onClick={() => setAmount(formatBalance(currentToken.balance, currentToken.decimals))}
                  >
                    Max
                  </button>
                </div>
                <div className="balance-info">
                  Available: {formatBalance(currentToken.balance, currentToken.decimals)} {currentToken.symbol}
                </div>
              </div>

              <div className="send-fee-row">
                <span className="fee-label">Network fee</span>
                <span className="fee-value">Available at mainnet</span>
              </div>

              <button
                className="button send-button"
                disabled={!recipient || !amount}
                onClick={handleSend}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <line x1="12" y1="19" x2="12" y2="5"></line>
                  <polyline points="5 12 12 5 19 12"></polyline>
                </svg>
                Send {currentToken.symbol}
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Private Key Password Modal */}
      {showPKModal && (
        <div className="modal-overlay" onClick={() => { setShowPKModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Export Private Key</h2>
              <button className="modal-close" onClick={() => { setShowPKModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <div className="settings-password-modal">
              <div className="form-group">
                <label className="form-label">Enter your password to continue</label>
                <input
                  type="password"
                  className={`form-input ${settingsPasswordError ? "input-error" : ""}`}
                  placeholder="Password"
                  value={settingsPassword}
                  onChange={(e) => { setSettingsPassword(e.target.value); setSettingsPasswordError(""); }}
                  onKeyDown={(e) => { if (e.key === "Enter") handleExportPK(); }}
                  autoFocus
                />
                {settingsPasswordError && <div className="error">{settingsPasswordError}</div>}
              </div>
              <div className="settings-modal-actions">
                <button className="button button-secondary" onClick={() => { setShowPKModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>Cancel</button>
                <button className="button" onClick={handleExportPK} disabled={!settingsPassword}>Confirm</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Seed Phrase Password Modal */}
      {showSeedModal && (
        <div className="modal-overlay" onClick={() => { setShowSeedModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Recovery Phrase</h2>
              <button className="modal-close" onClick={() => { setShowSeedModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <div className="settings-password-modal">
              <div className="form-group">
                <label className="form-label">Enter your password to continue</label>
                <input
                  type="password"
                  className={`form-input ${settingsPasswordError ? "input-error" : ""}`}
                  placeholder="Password"
                  value={settingsPassword}
                  onChange={(e) => { setSettingsPassword(e.target.value); setSettingsPasswordError(""); }}
                  onKeyDown={(e) => { if (e.key === "Enter") handleShowSeed(); }}
                  autoFocus
                />
                {settingsPasswordError && <div className="error">{settingsPasswordError}</div>}
              </div>
              <div className="settings-modal-actions">
                <button className="button button-secondary" onClick={() => { setShowSeedModal(false); setSettingsPassword(""); setSettingsPasswordError(""); }}>Cancel</button>
                <button className="button" onClick={handleShowSeed} disabled={!settingsPassword}>Confirm</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
