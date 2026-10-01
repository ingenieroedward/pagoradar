export type Bank = "nequi_negocios" | "nequi" | "bancolombia";
export type ChargeStatus = "pending" | "paid" | "expired" | "canceled";

export interface Account {
  id: string;
  name: string;
  address: string;
  ownerEmails: string[];
  banks: Bank[];
  tenantRef: string | null;
  status: "pending" | "active" | "disabled";
  confirmationCode: string | null;
  confirmationLink: string | null;
  confirmationAt: string | null;
  lastEmailAt: string | null;
  lastPaymentAt: string | null;
  payKey: string | null;
  payHolder: string | null;
  createdAt: string;
  setup: { forwardTo: string; gmailFilterFrom: string };
}

export interface AccountFields {
  name?: string;
  ownerEmails?: string[];
  banks?: Bank[];
  tenantRef?: string | null;
  payKey?: string | null;
  payHolder?: string | null;
  active?: boolean;
}

export interface Payment {
  id: string;
  appId: string;
  accountId: string | null;
  bank: Bank;
  method: string | null;
  methodText: string | null;
  amount: number;
  amountCents: number;
  currency: "COP";
  payerName: string | null;
  payerNameNormalized: string | null;
  payerBank: string | null;
  reference: string | null;
  transactionId: string | null;
  paidAt: string;
  receivedAt: string;
  chargeId?: string | null;
}

export interface Charge {
  id: string;
  status: ChargeStatus;
  /** What the customer must pay (unique among the account's open charges). */
  amount: number;
  amountCents: number;
  /** What you asked for. */
  baseAmount: number;
  /** amount - baseAmount, in pesos. */
  adjustment: number;
  currency: "COP";
  description: string | null;
  reference: string | null;
  payerName: string | null;
  metadata: Record<string, unknown> | null;
  account: { id: string; name?: string; tenantRef?: string | null };
  payTo: { key: string | null; holder: string | null; banks: Bank[] } | null;
  checkoutUrl: string;
  returnUrl: string | null;
  paymentId: string | null;
  /** How it got paid: the unique amount, the round amount asked for (only one charge asked it), or linked by hand. */
  match: "exact" | "approximate" | "manual" | null;
  /** What the payment brought (may differ from `amount` when match is "approximate" or "manual"). */
  paidAmount: number | null;
  createdAt: string;
  expiresAt: string;
  paidAt: string | null;
  canceledAt: string | null;
}

export interface CreateCharge {
  /** Receiving account id, or `tenantRef` to use that customer's account. */
  account?: string;
  tenantRef?: string;
  /** Whole pesos. */
  amount: number;
  currency?: "COP";
  description?: string;
  /** Your order id: unique per app; creating again with it returns the same charge. */
  reference?: string;
  /** Expected payer, used only to tell apart charges with the same amount. */
  payerName?: string;
  /** "up" (default) adds 1–999 pesos to make the amount unique, "down" subtracts them, "off" keeps it exact. */
  uniqueAmount?: "up" | "down" | "off";
  /** 5 to 10080; default 30. */
  expiresInMinutes?: number;
  returnUrl?: string;
  metadata?: Record<string, unknown>;
}

export type PagoradarEvent =
  | { id: string; type: "payment.received" | "payment.test"; createdAt: string; source: string; data: Payment & { account: { id: string; name: string; tenantRef: string | null } | null; charge: { id: string; reference: string | null } | null } }
  | { id: string; type: "charge.paid"; createdAt: string; source: string; data: Charge & { payment: Payment; late: boolean; manual?: boolean } }
  | { id: string; type: "charge.expired"; createdAt: string; source: string; data: Charge }
  | { id: string; type: "account.confirmation_code"; createdAt: string; source: string; data: { account: { id: string; name: string; tenantRef: string | null; address: string }; code: string | null; link: string | null } }
  | { id: string; type: "account.activated"; createdAt: string; source: string; data: { account: { id: string; name: string; tenantRef: string | null; address: string } } };

export class PagoradarError extends Error {
  status: number | null;
  body: unknown;
}

export class Pagoradar {
  constructor(options: { apiKey: string; baseUrl: string; fetch?: typeof fetch; timeoutMs?: number });
  accounts: {
    create(fields: AccountFields & { name: string; ownerEmails: string[] }): Promise<Account>;
    list(filters?: { tenantRef?: string }): Promise<Account[]>;
    get(id: string): Promise<Account>;
    update(id: string, fields: AccountFields): Promise<Account>;
    remove(id: string): Promise<{ id: string; deleted: boolean; disabled?: boolean }>;
  };
  charges: {
    create(fields: CreateCharge): Promise<Charge>;
    list(filters?: { status?: ChargeStatus; reference?: string; account?: string; tenantRef?: string; limit?: number; offset?: number }): Promise<{ charges: Charge[]; total: number }>;
    get(id: string): Promise<Charge>;
    cancel(id: string): Promise<Charge>;
    pay(id: string, paymentId: string): Promise<Charge>;
  };
  payments: {
    list(filters?: { since?: string; limit?: number; account?: string; tenantRef?: string }): Promise<{ payments: Payment[]; next: string | null }>;
  };
  webhooks: { test(): Promise<unknown> };
  request<T = unknown>(method: string, path: string, body?: unknown): Promise<T>;
}

export function verifySignature(rawBody: string | Uint8Array, header: string | null | undefined, secret: string, options?: { toleranceSec?: number; now?: number }): boolean;
export function constructEvent(rawBody: string | Uint8Array, header: string | null | undefined, secret: string, options?: { toleranceSec?: number; now?: number }): PagoradarEvent;
