// Every failure the Get access page can hit, as one plain sentence and a next step. The wallet's
// and the SDK's own messages are kept on `detail` for the curious; the visitor reads `text`.
// Pure and testable: test/stake-site.selftest.mjs feeds it the errors the SDK and wallets raise.

const USER_REJECTED = new Set([4001, "ACTION_REJECTED"]);

function messageOf(error) {
  return String(error?.shortMessage || error?.message || error || "").trim();
}

function walletCode(error) {
  const code = error?.code ?? error?.cause?.code ?? error?.info?.error?.code ?? error?.error?.code;
  return code;
}

export function explainError(error, context = {}) {
  const { action = "stake", chainName = "Sepolia", need = null, balance = null, proverMb = null } = context;
  const message = messageOf(error);
  const lower = message.toLowerCase();
  const code = walletCode(error);
  const detail = message;

  if (!error) return { text: `${action} failed for no stated reason. Try again.`, next: null, detail };
  if (/no compatible ethereum wallet|no eip-1193 provider/i.test(message)) {
    return { text: "No Ethereum wallet was found in this browser.", next: "Install one (MetaMask, Rabby or Brave's wallet) and reload, or use the CLI path below, which needs no browser wallet.", detail };
  }
  if (USER_REJECTED.has(code) || /user rejected|user denied|rejected the request|cancell?ed/i.test(message)) {
    return { text: "You cancelled in the wallet. Nothing was sent.", next: "Press the button again when you are ready.", detail };
  }
  if (code === -32002 || /already pending|request already pending/i.test(message)) {
    return { text: "The wallet already has a request open.", next: "Open the wallet, finish or dismiss that request, then try again.", detail };
  }
  if (/wallet is on chain|is required\.?$|wrong chain|chain mismatch|unrecognized chain/i.test(message)) {
    return { text: `The wallet is not on ${chainName}.`, next: `Switch the wallet's network to ${chainName} and try again. Most wallets let this page do the switch when you connect.`, detail };
  }
  if (/staking contract is not deployed|not deployed on/i.test(message)) {
    return { text: `The staking contract is not on the network your wallet is using.`, next: `Switch the wallet to ${chainName}. If it already is, the wallet's RPC is answering for another chain.`, detail };
  }
  if (/insufficient funds|needs at least|exceeds the balance|not enough/i.test(message)) {
    const have = balance ? ` This wallet has ${balance}.` : "";
    const want = need ? ` The stake needs ${need} plus gas.` : "";
    return { text: `Not enough ${chainName} ETH in this wallet.${have}${want}`, next: `Get ${chainName} ETH from a faucet below, or send your commitment to a sponsor who stakes for you.`, detail };
  }
  if (/reverted/i.test(message)) {
    return { text: `${chainName} rejected the transaction, so nothing changed on chain beyond the gas it burned.`, next: "If this commitment was staked before, check its status below. Otherwise reload and try once more; if it reverts again, report it with the transaction link.", detail };
  }
  if (/contract bond .* record says|refusing to send/i.test(message)) {
    return { text: "The contract's bond differs from the number this page shows, so nothing was sent.", next: "The page is behind the deployment. Reload; if it persists, report it.", detail };
  }
  if (/exiting and cannot be registered/i.test(message)) {
    return { text: "This identity is still unbonding, so it cannot be staked again yet.", next: "Create a new identity to stake now, or wait for the unbonding period to finish and withdraw this one.", detail };
  }
  if (/only an active membership can start an exit/i.test(message)) {
    return { text: "This identity is not active, so there is nothing to exit.", next: "Check its status below. An identity that was never staked, or already exited, cannot exit.", detail };
  }
  if (/still unbonding/i.test(message)) {
    return { text: "The bond is still unbonding.", next: "Check the status below for the time left, then withdraw.", detail };
  }
  if (/no finished exit to withdraw/i.test(message)) {
    return { text: "There is no finished exit to withdraw for this identity.", next: "Start an exit first, wait out the unbonding period, then withdraw.", detail };
  }
  if (/proof context differs/i.test(message)) {
    return { text: "The contract's proof context does not match this page's, so the page refused to prove.", next: "The page is behind the deployment. Reload; if it persists, report it.", detail };
  }
  if (/\.wasm|zkey|prover|snarkjs|witness|groth16|wasm-unsafe-eval|webassembly/i.test(message)) {
    const size = proverMb ? ` (${proverMb} MB)` : "";
    return { text: `The in-browser prover${size} failed to load or run.`, next: "Check the connection and try again. If your browser blocks WebAssembly, use the CLI commands below instead.", detail };
  }
  if (/identity file|identity json|identitysecret|not a valid shadenet identity/i.test(message)) {
    return { text: message, next: "Choose the file this page downloaded, or one written by shadenet init or shadenet enroll.", detail };
  }
  if (/offers tiers|not one of them|not offered/i.test(message)) {
    return { text: message, next: "Only the tiers listed on this page exist on this canopy.", detail };
  }
  if (/canonical, non-zero|decimal field element|recipient|zero address/i.test(message)) {
    return { text: message, next: null, detail };
  }
  if (/rpc|eth_|network error|failed to fetch|timeout|timed out|could not detect network|missing revert data/i.test(lower)) {
    return { text: `Could not reach ${chainName} through the wallet's RPC.`, next: "Try again in a moment. If it keeps failing, switch the wallet's RPC endpoint for Sepolia.", detail };
  }
  if (/clipboard/i.test(message)) {
    return { text: "Could not use the clipboard.", next: "Select the value on the page and copy it by hand.", detail };
  }
  return { text: message || `${action} failed.`, next: "Try again. If it repeats, report it with the text above.", detail };
}

export function formatExplanation(explained) {
  return explained.next ? `${explained.text} ${explained.next}` : explained.text;
}
