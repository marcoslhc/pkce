/* eslint-disable @typescript-eslint/no-unused-vars */
jest.mock("isomorphic-webcrypto", () => {
  return {
    getRandomValues: jest.fn((buffer: Uint16Array) => {
      const array: number[] = "somerandomstring.somerandoms"
        .split("")
        .map((x: string) => x.codePointAt(0) as number);
      buffer.set(array);
    }),
    subtle: {
      digest: jest.fn(() => Buffer.from("someotherrandomstring")),
    },
  };
});
import * as undertest from "../";
import crypto from "isomorphic-webcrypto";

describe("PCKE", () => {
    let token: {
    verifier: string;
    code_challenge: string;
    method: "SHA256";
  };

  const expectedToken = {
    verifier:
      "07306f06d06507206106e06406f06d07307407206906e06702e07306f06d06507206106e06406f06d073",
    code_challenge: "c29tZW90aGVycmFuZG9tc3RyaW5n",
    method: "SHA256",
  };

  beforeEach(async () => {
    token = await undertest.createPKCE();
  });
  test("createPKCE creates a random token", async () => {
    expect.hasAssertions();
    console.log(process.env);
    expect(token.code_challenge).toBe(expectedToken.code_challenge);
    expect(token.verifier).toBe(expectedToken.verifier);
    expect(crypto.getRandomValues).toHaveBeenCalled();
  });
  test("verify", async () => {
    expect.hasAssertions();
    expect(await undertest.verify(token.code_challenge, token.verifier)).toBe(
      true
    );
  });
});

describe.each`
        encoding        |   expected
        ${"base64"}     |   ${ "c29tZXJhbmRvbSBzdHJpbmcgQA==" }
        ${"base64url"}  |   ${ "c29tZXJhbmRvbSBzdHJpbmcgQA" }
    `("$encoding", ({encoding, expected}) => {
        test(`should encode with ${encoding}`, () => {
            expect(undertest.base64EncodeBase("somerandom string @", encoding)).toBe(expected);
        });
    });

describe("base64EncodeBase", () => {
  test.each`
    encoding       | expected
    ${"base64"}    | ${"c29tZXJhbmRvbSBzdHJpbmcgQA=="}
    ${"base64url"} | ${"c29tZXJhbmRvbSBzdHJpbmcgQA"}
  `(
    "calling with $encoding should return the correct value",
    ({ encoding, expected }) => {
      expect.hasAssertions();
      expect(undertest.base64EncodeBase("somerandom string @", encoding)).toBe(
        expected
      );
    }
  );
});
