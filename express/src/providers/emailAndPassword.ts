import { z } from 'zod'
import { Algorithm, sign } from 'jsonwebtoken'
import { compare } from 'bcrypt'

const emailAndPasswordSchema = z.object({
  type: z.enum(['emailAndPassword']),
  default_fields: z
    .object({
      email: z.string().email(),
      username: z.string().min(1).optional(),
      password: z.string().min(1),
    })
    .or(z.string().min(1)),
})

type LoginResponse = {
  status: number
  body?: string | Record<PropertyKey, unknown>
}
type DatabaseResponse =
  | { success: true; password: string; databaseFailure?: false }
  | { success: false; password: undefined; databaseFailure: boolean }

type Body = { type: 'emailAndPassword' } & Record<PropertyKey, unknown>

const emailAndPasswordLogin = (providerOptions: {
  secretOrPrivateKey: string
  expiresIn?: string | number
  algorithm?: Algorithm
  getUserLoginData: (
    email: string,
    username?: string
  ) => Promise<UserHashedPassword>
}) => {
  const { secretOrPrivateKey, expiresIn, algorithm, getUserLoginData } =
    providerOptions
  const builtHandler = async (
    req: z.infer<typeof emailAndPasswordSchema>
  ): Promise<LoginResponse> => {
    const { success: successParsingBody, data } =
      emailAndPasswordSchema.safeParse(req)

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
