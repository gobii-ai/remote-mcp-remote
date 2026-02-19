import { describe, it, expect, afterEach, vi } from 'vitest'
import { EventEmitter } from 'events'
import { createLazyAuthCoordinator, type AuthCoordinatorOptions } from './coordination'

function mockResponse(status: number, body = ''): Response {
  return {
    status,
    text: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function buildBridgeCoordinator(overrides: Partial<AuthCoordinatorOptions> = {}) {
  const options: AuthCoordinatorOptions = {
    callbackPort: 3333,
    authTimeoutMs: 40,
    authMode: 'bridge',
    authBridgePollUrl: 'https://bridge.example.com/poll',
    authBridgePollIntervalMs: 1,
    ...overrides,
  }

  return createLazyAuthCoordinator('server-hash', new EventEmitter(), options)
}

describe('bridge auth coordination', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('returns code when bridge responds with code field', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(200, '{"code":"auth-code-1"}'))
    vi.stubGlobal('fetch', fetchMock)

    const coordinator = buildBridgeCoordinator()
    const authState = await coordinator.initializeAuth()
    await expect(authState.waitForAuthCode()).resolves.toBe('auth-code-1')
  })

  it('returns code when bridge responds with authorization_code field', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(200, '{"authorization_code":"auth-code-2"}'))
    vi.stubGlobal('fetch', fetchMock)

    const coordinator = buildBridgeCoordinator()
    const authState = await coordinator.initializeAuth()
    await expect(authState.waitForAuthCode()).resolves.toBe('auth-code-2')
  })

  it('times out when bridge returns non-JSON body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(200, 'plain-text-code'))
    vi.stubGlobal('fetch', fetchMock)

    const coordinator = buildBridgeCoordinator({ authTimeoutMs: 10 })
    const authState = await coordinator.initializeAuth()

    await expect(authState.waitForAuthCode()).rejects.toThrow('Timed out waiting for auth code from bridge')
    expect(fetchMock).toHaveBeenCalled()
  })

  it('times out when bridge remains pending', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(202))
    vi.stubGlobal('fetch', fetchMock)

    const coordinator = buildBridgeCoordinator({ authTimeoutMs: 10 })
    const authState = await coordinator.initializeAuth()

    await expect(authState.waitForAuthCode()).rejects.toThrow('Timed out waiting for auth code from bridge')
    expect(fetchMock).toHaveBeenCalled()
  })

  it('fails immediately when bridge session is expired', async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(410))
    vi.stubGlobal('fetch', fetchMock)

    const coordinator = buildBridgeCoordinator()
    const authState = await coordinator.initializeAuth()

    await expect(authState.waitForAuthCode()).rejects.toThrow('Auth bridge session expired')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
