import { describe, expect, it } from 'vitest'
import { LoginHandlerBuilder } from '../../src/handlers/login'

describe('Unit test built login handler', () => {
  it('Error when build with zero providers', () => {
    expect(() => LoginHandlerBuilder.new().build()).toThrowError()
  })

  it('Error with one provider and request without a type in the body', () => {})

  it('Error with one provider and request with a wrong type', () => {})

  it('Success with one provider and request with a correct payload', () => {})

  it('Error with multiple providers and request without a type in the body', () => {})

  it('Error with multiple providers and request with a wrong type', () => {})

  it('Success with multiple providers and request with a correct payload', () => {})
})
