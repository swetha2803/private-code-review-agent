import axios from "axios";

export async function submitTransfer(accountNumber: string, beneficiaryId: string, amount: number) {
  return axios.post("/api/transfer/submit", {
    accountNumber,
    beneficiaryId,
    amount,
  });
}

export async function getStatement(accountId: string) {
  return fetch(`/api/account/${accountId}/statement`);
}

export async function addBeneficiary(payload: unknown) {
  return axios.post("/api/beneficiary/add", payload);
}
