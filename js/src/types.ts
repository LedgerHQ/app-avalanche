export interface ResponseBase {
  errorMessage: string
  returnCode: number
}

export interface ResponseAddress extends ResponseBase {
  publicKey: Buffer
  hash: Buffer
}

export interface ResponseXPub extends ResponseBase {
  publicKey: Buffer
  chain_code: Buffer
}

export interface ResponseVersion extends ResponseBase {
  testMode: boolean
  major: number
  minor: number
  patch: number
  deviceLocked: boolean
  targetId: string
}

export interface ResponseAppInfo extends ResponseBase {
  appName: string
  appVersion: string
  flagLen: number
  flagsValue: number
  flagRecovery: boolean
  flagSignedMcuCode: boolean
  flagOnboarded: boolean
  flagPINValidated: boolean
}

export interface ResponseSign extends ResponseBase {
  hash: Buffer
  signature: Buffer
}

export interface ResponseWalletId extends ResponseBase {
  id: Buffer
}