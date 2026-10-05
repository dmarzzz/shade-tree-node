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
  const { action = "stake", chainName = "Sepolia", need = null, balance = null } = context;
  const message = messageOf(error);
  const lower = message.toLowerCase();
  const code = walletCode(error);
  const detail = message;

  if (!error) return { text: `${action} failed for no stated reason. Try again.`, next: null, detail };
  if (/no compatible ethereum wallet|no eip-1193 provider/i.test(message)) {
    return { text: "No Ethereum wallet was found in this browser.", next: "On a phone, open this page inside your wallet app. The terminal command needs no browser wallet.", detail };
  }
  if (USER_REJECTED.has(code) || /user rejected|user denied|rejected the request|cancell?ed/i.test(message)) {
    return { text: "You cancelled in the wallet. Nothing was sent.", next: "Press the button again when you are ready.", detail };
  }
  if (code === -32002 || /already pending|request already pending/i.test(message)) {
    return { text: "The wallet already has a request open.", next: "Open the wallet, finish or dismiss that request, then try again.", detail };
  }
  if (/wallet is on chain|is required\.?$|wrong chain|chain mismatch|unrecognized chain/i.test(message)) {
    return { text: `The wallet is not on ${chainName}.`, next: `Switch its network to ${chainName} and connect again.`, detail };
  }
  if (/staking contract is not deployed|not deployed on/i.test(message)) {
    return { text: `The staking contract is not on the network your wallet is using.`, next: `Switch the wallet to ${chainName}. If it already is, the wallet's RPC is answering for another chain.`, detail };
  }
  if (/insufficient funds|needs at least|exceeds the balance|not enough/i.test(message)) {
    const have = balance ? ` This wallet has ${balance}.` : "";
    const want = need ? ` The stake needs ${need} plus gas.` : "";
    return { text: `Not enough ${chainName} ETH in this wallet.${have}${want}`, next: "Faucets are under Leave and details. Someone else can stake for you: copy the link and send it to them.", detail };
  }
  if (/reverted/i.test(message)) {
    return { text: `${chainName} rejected the transaction, so nothing changed on chain beyond the gas it burned.`, next: "Reload and connect the wallet to see whether this identity commitment is already staked. If it reverts again, report it with the transaction link.", detail };
  }
  if (/contract bond .* record says|refusing to send/i.test(message)) {
    return { text: "The contract's bond differs from the number this page shows, so nothing was sent.", next: "The page is behind the deployment. Reload; if it persists, report it.", detail };
  }
  if (/exiting and cannot be registered/i.test(message)) {
    return { text: "This identity is still unbonding, so it cannot be staked again yet.", next: "Make a new identity with shadenet init to stake now, or wait for the unbonding period to finish and withdraw this one.", detail };
  }
  if (/offers tiers|not one of them|not offered/i.test(message)) {
    return { text: message, next: "Only the tiers listed on this page exist on this canopy.", detail };
  }
  if (/canonical, non-zero|decimal field element|identity commitment/i.test(message)) {
    return { text: message, next: null, detail };
  }
  if (/rpc|eth_|network error|failed to fetch|timeout|timed out|could not detect network|missing revert data/i.test(lower)) {
    return { text: `Could not reach ${chainName} through the wallet's RPC.`, next: "Try again in a moment. If it keeps failing, switch the wallet's RPC endpoint for Sepolia.", detail };
  }
  if (/clipboard/i.test(message)) {
    return { text: "Could not use the clipboard.", next: "Select the text on the page and copy it by hand.", detail };
  }
  return { text: message || `${action} failed.`, next: "Try again. If it repeats, report it with the text above.", detail };
}

export function formatExplanation(explained) {
  return explained.next ? `${explained.text} ${explained.next}` : explained.text;
}
