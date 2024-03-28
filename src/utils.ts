/**
 * @description Creates a version value using the major and minor versions.
 */
export function createVersion(majorVersion: number, minorVersion: number): number {
  return ((majorVersion & 0xF) << 4) | (minorVersion & 0xF)
}

/**
 * @description Insinuates that the functional is not implemented.
 * @throws Error
 */
export function notImplemented(part: string): never {
  throw new Error(`${part} is Not implemented`)
}
