import { z } from 'zod'
import { Algorithm, sign } from 'jsonwebtoken'
import { compare } from 'bcrypt'
import { LoginResponse, ProviderHandlerBuilder } from '../handlers/login'

const emailAndPasswordSchema = z.object({
  default_fields: z
    .object({
      email: z.string().email(),
      username: z.string().min(1).optional(),
      password: z.string().min(1),
    })
    .or(z.string().min(1)),
})

type Body = Record<PropertyKey, unknown>

type DatabaseResponse =
  | { success: true; password: string; databaseFailure?: false }
  | { success: false; password: undefined; databaseFailure: boolean }

type EmailAndPasswordOptions = {
  secretOrPrivateKey: string
  expiresIn?: string | number
  algorithm?: Algorithm
  getUserLoginData: (
    email: string,
    username?: string
  ) => Promise<DatabaseResponse>
}

const emailAndPasswordLogin: ProviderHandlerBuilder<EmailAndPasswordOptions> = (
  providerOptions: EmailAndPasswordOptions
) => {
  const { secretOrPrivateKey, expiresIn, algorithm, getUserLoginData } =
    providerOptions
  const builtHandler = async (req: Body): Promise<LoginResponse> => {
    const { success: successParsingBody, data } =
      await emailAndPasswordSchema.safeParseAsync(req)

    if (!successParsingBody) {
      return { status: 422 }
    }

    const { default_fields } = data

    if (typeof default_fields === 'string') {
      return {
        status: 422,
        body: 'Token revalidation not yet supported on this route',
      }
    }

    const { email, username, password } = default_fields

    const {
      success: fetchedHashedUserPassword,
      password: userPasswordHash,
      databaseFailure,
    } = await getUserLoginData(email, username)

    if (databaseFailure) {
      return { status: 500 }
    }

    if (!fetchedHashedUserPassword) {
      return { status: 400 }
    }

    const samePassword = await compare(password, userPasswordHash)
    if (samePassword) {
      const responseJWT = sign({ email }, secretOrPrivateKey, {
        expiresIn: expiresIn ?? '1d',
        algorithm: algorithm ?? 'HS256',
      })

      return { status: 200, body: responseJWT }
    }

    return { status: 400 }
  }

  return builtHandler
}

const emailAndPasswordSignin = async (req: Body) => {}

const emailAndPasswordLogout = async (req: Body) => {}

export const emailAndPasswordProvider = {
  loginBuilder: emailAndPasswordLogin,
  signinBuilder: emailAndPasswordSignin,
  logoutBuilder: emailAndPasswordLogout,
} as const
