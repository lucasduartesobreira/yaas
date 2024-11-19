import { beforeAll, describe, expect, it } from 'vitest'
import { emailAndPasswordProvider } from '../../src/providers/emailAndPassword'
import { generateKeyPairSync } from 'crypto'
import { hashSync } from 'bcrypt'

describe('Unit test Email and Password Login', () => {
  let privateKey: string
  let publicKey: string
  beforeAll(() => {
    const result = generateKeyPairSync('rsa', {
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

    privateKey = result.privateKey
    publicKey = result.publicKey
  })

  it('Error with sending wrong content to login handler', async () => {
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: false,
        password: undefined,
        databaseFailure: false,
      }),
    })

    const { status } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: {
        email: 'some_email@example.com',
        username: 'some_username',
      } as any,
    })

    expect(status === 422).toBeTruthy()
  })

  it('Error with sending a token to revalidation', async () => {
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: false,
        password: undefined,
        databaseFailure: false,
      }),
    })

    const { status, body } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: 'some_token_clearly_wrong',
    })

    expect(status === 422).toBeTruthy()
    expect(body).toBe('Token revalidation not yet supported on this route')
  })

  it("Error when database can't find a user", async () => {
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: false,
        password: undefined,
        databaseFailure: false,
      }),
    })

    const { status } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: { email: 'some_email@example.com', password: 'password' },
    })

    expect(status === 400).toBeTruthy()
  })

  it("Error when database is offline or can't handle the request", async () => {
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: false,
        password: undefined,
        databaseFailure: true,
      }),
    })

    const { status } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: { email: 'some_email@example.com', password: 'password' },
    })

    expect(status === 500).toBeTruthy()
  })

  it('Error when sending a wrong password', async () => {
    const hashedPassoword = hashSync('some_really_strong_password_xdd', 10)
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: true,
        password: hashedPassoword,
      }),
    })

    const { status } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: { email: 'some_email@example.com', password: 'password' },
    })

    expect(status === 400).toBeTruthy()
  })

  it('Success when sending a valid email and password', async () => {
    const hashedPassoword = hashSync('some_really_strong_password_xdd', 10)
    const loginHandler = emailAndPasswordProvider.loginBuilder({
      secretOrPrivateKey: privateKey,
      getUserLoginData: async () => ({
        success: true,
        password: hashedPassoword,
      }),
    })

    const { status, body } = await loginHandler({
      type: 'emailAndPassword',
      default_fields: {
        email: 'some_email@example.com',
        password: 'some_really_strong_password_xdd',
      },
    })

    expect(status === 200).toBeTruthy()
    expect(body).not.toBeNull()
  })
})
