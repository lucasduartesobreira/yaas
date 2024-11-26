import { describe, expect, it } from 'vitest'
import { LoginHandlerBuilder } from '../../src/handlers/login'
import { emailAndPasswordProvider } from '../../src/providers/emailAndPassword'
import { hashSync } from 'bcrypt'
import { generateKeyPairSync } from 'crypto'

describe('Unit test built login handler', () => {
  it('Error when build with zero providers', () => {
    expect(() => LoginHandlerBuilder.new().build()).toThrowError()
  })

  it('Error with one provider and request without a type in the body', async () => {
    const handler = LoginHandlerBuilder.new()
      .addProvider({
        provider: emailAndPasswordProvider.loginBuilder,
        providerName: 'emailAndPassword',
        providerOptions: {
          getUserLoginData: async () =>
            ({
              success: false,
              databaseFailure: false,
              password: undefined,
            }) as const,
          secretOrPrivateKey: 'sshhhhhhhhh',
        },
      })
      .build()

    const requestBody = { bad: 'request' }
    const request = { body: requestBody } as any

    const response = {
      _status: -1,
      status(this, status: number) {
        this._status = status
        return this
      },
      _body: '',
      send(body: any) {
        this._body = body
        return this
      },
    } as any

    await handler(request, response)

    expect(response._status).toBe(422)
    expect(response._body).toBe('Authentication Provider not specified')
  })

  it('Error with one provider and request with a wrong type', async () => {
    const handler = LoginHandlerBuilder.new()
      .addProvider({
        provider: emailAndPasswordProvider.loginBuilder,
        providerName: 'emailAndPassword',
        providerOptions: {
          getUserLoginData: async () =>
            ({
              success: false,
              databaseFailure: false,
              password: undefined,
            }) as const,
          secretOrPrivateKey: 'sshhhhhhhhh',
        },
      })
      .build()

    const requestBody = { type: 'notAProvider' }
    const request = { body: requestBody } as any

    const response = {
      _status: -1,
      status(this, status: number) {
        this._status = status
        return this
      },
      _body: '',
      send(body: any) {
        this._body = body
        return this
      },
    } as any

    await handler(request, response)

    expect(response._status).toBe(422)
    expect(response._body).toBe(
      'Provider not specified. Those are the providers already defined: emailAndPassword'
    )
  })

  it('Success with one provider and request with a correct payload', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      },
    })

    const hashedPassoword = hashSync('some_really_strong_password_xdd', 10)
    const handler = LoginHandlerBuilder.new()
      .addProvider({
        provider: emailAndPasswordProvider.loginBuilder,
        providerName: 'emailAndPassword',
        providerOptions: {
          secretOrPrivateKey: privateKey,
          getUserLoginData: async () =>
            ({
              success: true,
              password: hashedPassoword,
            }) as const,
        },
      })
      .build()

    const requestBody = {
      type: 'emailAndPassword',
      default_fields: {
        email: 'some_email@example.com',
        password: 'some_really_strong_password_xdd',
      },
    }
    const request = { body: requestBody } as any

    const response = {
      _status: -1,
      status(this, status: number) {
        this._status = status
        return this
      },
      _body: '',
      send(body: any) {
        this._body = body
        return this
      },
    } as any

    await handler(request, response)

    expect(response._status).toBe(200)
    expect(response._body.length).toBeGreaterThan(1)
  })

  it('Error with multiple providers and request without a type in the body', () => {})

  it('Error with multiple providers and request with a wrong type', () => {})

  it('Success with multiple providers and request with a correct payload', () => {})
})
