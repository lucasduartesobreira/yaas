import { Request, Response } from 'express'
type ProvidersName = string

export type LoginResponse = {
  status: number
  body?: string | Record<PropertyKey, unknown>
}

type OptionsUtility<Providers extends ProvidersName[]> = {
  [Key in Providers[number]]: Record<PropertyKey, unknown>
}

type ProvidersBuilder<
  Providers extends ProvidersName[],
  Options extends OptionsUtility<Providers>,
> = {
  [Key in Providers[number]]: ProviderHandlerBuilder<Options[Key]>
}

type ProvidersBuilt<Providers extends ProvidersName[]> = {
  [Key in Providers[number]]: (
    req: Record<PropertyKey, unknown>
  ) => Promise<LoginResponse>
}

export type ProviderHandlerBuilder<
  ProviderOptions extends Record<PropertyKey, unknown>,
> = (
  providersOptions: ProviderOptions
) => (req: Record<PropertyKey, unknown>) => Promise<LoginResponse>

type RequestBody<Providers extends ProvidersName[]> = {
  type: Providers[number] | string
} & Record<PropertyKey, unknown>

const buildNotFoundProviderMessage = (providers: string[]) => {
  const definedProvidersAsString = providers.join(', ')

  return `Provider not specified. Those are the providers already defined: ${definedProvidersAsString}`
}

const buildProvidersLoginHandler = <
  Providers extends ProvidersName[],
  Options extends OptionsUtility<Providers>,
>(
  providers: ProvidersBuilder<Providers, Options>,
  options: Options
) => {
  const handlersBuiltAsTuple = Object.entries<any>(providers).map(
    <T extends Providers[number]>([providerName, providerHandlerBuilder]: [
      T,
      ProviderHandlerBuilder<Options[T]>,
    ]): [
      Providers[number],
      (req: Record<PropertyKey, unknown>) => Promise<LoginResponse>,
    ] => [providerName, providerHandlerBuilder(options[providerName])] as const
  )

  const handlersBuilt = Object.fromEntries(
    handlersBuiltAsTuple
  ) as ProvidersBuilt<Providers>

  return handlersBuilt
}

export class LoginHandlerBuilder<
  Providers extends ProvidersName[],
  Options extends OptionsUtility<Providers>,
> {
  private constructor(
    private providers: ProvidersBuilder<Providers, Options>,
    private options: Options
  ) {}

  static new(): LoginHandlerBuilder<[], {}> {
    return new LoginHandlerBuilder<[], {}>({}, {})
  }

  addProvider<
    T extends string,
    ProviderOptions extends Record<PropertyKey, unknown>,
  >({
    provider,
    providerName,
    providerOptions,
  }: {
    provider: ProviderHandlerBuilder<ProviderOptions>
    providerName: T
    providerOptions: ProviderOptions
  }): LoginHandlerBuilder<
    [...Providers, T],
    Options & { [Key in T]: ProviderOptions }
  > {
    const test = new LoginHandlerBuilder<
      [...Providers, T],
      Options & { [Key in T]: ProviderOptions }
    >(
      { ...this.providers, [providerName]: provider },
      { ...this.options, [providerName]: providerOptions }
    )

    return test
  }

  build() {
    const providersKeys = Object.keys(this.providers)

    if (providersKeys.length === 0) {
      throw Error("Can't build login handler with zero providers defined")
    }

    const NotFoundProviderErrorMessage =
      buildNotFoundProviderMessage(providersKeys)

    const builtProviderLoginHandlers = buildProvidersLoginHandler(
      this.providers,
      this.options
    )

    const handler = async (
      req: Request<
        Record<PropertyKey, unknown>,
        unknown,
        RequestBody<Providers>
      >,
      res: Response
    ) => {
      const body = req.body

      if (!('type' in body)) {
        res.status(422).send('Authentication Provider not specified')
        return res
      }

      const { type } = body
      if (type in builtProviderLoginHandlers) {
        const providerHandler = builtProviderLoginHandlers[type]
        const result = await providerHandler(body)

        const { status, body: bodyResponse } = result
        res.status(status).send(bodyResponse)
        return res
      }

      res.status(422).send(NotFoundProviderErrorMessage)
    }

    return handler
  }
}
