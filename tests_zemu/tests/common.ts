import { DEFAULT_START_OPTIONS, IDeviceModel, ButtonKind } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

// Default to 'app' if app is not set
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')
const APP_PATH_ST = Resolve('../app/output/app_stax.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const eth_models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const defaultOptions = (m: IDeviceModel, is_address = false) => {
  let approveAction = ButtonKind.ApproveHoldButton
  let approveKeyword = ''

  if (m.name == 'stax' && is_address) {
    approveKeyword = 'Show as QR'
    approveAction = ButtonKind.ApproveTapButton
  }

  return {
    ...DEFAULT_START_OPTIONS,
    logging: true,
    custom: `-s "${APP_SEED}"`,
    approveAction,
    approveKeyword,
    model: m.name,
  }
}

export const ROOT_PATH = "m/44'/9000'/0'"
export const APP_DERIVATION = "m/44'/9000'/0'/0/0"
export const ETH_DERIVATION = "m/44'/60'/0'/0'"
export const BTC_PATH = "m/44'/60'/0'"

type MapCartesian<T extends any[][]> = {
  [P in keyof T]: T[P] extends Array<infer U> ? U : never
}

export const cartesianProduct = <T extends any[][]>(...arr: T): MapCartesian<T>[] =>
  arr.reduce((a, b) => a.flatMap(c => b.map(d => [...c, d])), [[]]) as MapCartesian<T>[]