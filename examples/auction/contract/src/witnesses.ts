/*
 * This file defines the shape of the auction's private state,
 * as well as the single witness function that accesses it.
 */

import { CurvePoint, WitnessContext } from '@midnight-ntwrk/compact-runtime';
import { CompactCredential, Ledger } from './managed/auction/contract/index.cjs';

/* **********************************************************************
 * The only hidden state needed by the auction contract is
 * the user's secret key.  Some of the library code and
 * compiler-generated code is parameterized by the type of our
 * private state, so we define a type for it and a function to
 * make an object of that type.
 */

export type AuctionPrivateState = {
  // EXERCISE 1a: FILL IN A REPRESENTATION OF THE PRIVATE STATE
  readonly secretKey: Uint8Array;
  readonly jwt: string;
  readonly ownerPK: CurvePoint;
  //readonly issuerPK: CurvePoint; // TODO issuerPK
};

export type JWTInfo = {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signature: string;
};

export type VCPayload = {
  vc: {
    credentialSubject: {
      birthDate: string;
      nationalId: string;
      givenName: string;
      familyName: string;
      id: string;
    };
  };
  iss: string;
  nbf: number;
  exp: number;
  sub: string;
};


export const createAuctionPrivateState = (secretKey: Uint8Array, jwt: string, ownerPK: CurvePoint) => ({
  // EXERCISE 1b: INITIALIZE THE OBJECT OF TYPE AuctionPrivateState
  secretKey,
  jwt,
  ownerPK,
});


export const parseJwtPayload = (jwt: string): JWTInfo => {
  const [headerBase64, payloadBase64, signatureBase64] = jwt.split('.');
  const header = Buffer.from(headerBase64, 'base64').toString();
  const payload = Buffer.from(payloadBase64, 'base64').toString();
  const jwtInfo: JWTInfo = {
    header: JSON.parse(header),
    payload: JSON.parse(payload),
    signature: signatureBase64
  };

  return jwtInfo;
}

/* **********************************************************************
 * The witnesses object for the auction contract is an object
 * with a field for each witness function, mapping the name of the function
 * to its implementation.
 *
 * The implementation of each function always takes as its first argument
 * a value of type WitnessContext<L, PS>, where L is the ledger object type
 * that corresponds to the ledger declaration in the Compact code, and PS
 *  is the private state type, like AuctionPrivateState defined above.
 *
 * A WitnessContext has three
 * fields:
 *  - ledger: T
 *  - privateState: PS
 *  - contractAddress: string
 *
 * The other arguments (after the first) to each witness function
 * correspond to the ones declared in Compact for the witness function.
 * The function's return value is a tuple of the new private state and
 * the declared return value.  In this case, that's a AuctionPrivateState
 * and a Uint8Array (because the contract declared a return value of Bytes[32],
 * and that's a Uint8Array in TypeScript).
 *
 * The local_secret_key witness does not need the ledger or contractAddress
 * from the WitnessContext, so it uses the parameter notation that puts
 * only the binding for the privateState in scope.
 */

export const witnesses = {
  local_secret_key: ({ privateState }: WitnessContext<Ledger, AuctionPrivateState>): [AuctionPrivateState, Uint8Array] => [
    // EXERCISE 2: WHAT ARE THE CORRECT TWO VALUES TO RETURN HERE?
    privateState,
    privateState.secretKey,
  ],


  get_credential_from_jwt: ({ privateState }: WitnessContext<Ledger, AuctionPrivateState>): [AuctionPrivateState, CompactCredential] => {
    const jwtInfo: JWTInfo = parseJwtPayload(privateState.jwt);
    const payload = jwtInfo.payload as VCPayload;
    const subject = payload.vc.credentialSubject;

    const credential: CompactCredential = {
      firstName: new Uint8Array(Buffer.from(subject.givenName.padEnd(80, ' '))),
      lastName: new Uint8Array(Buffer.from(subject.familyName.padEnd(80, ' '))),
      birthDate: BigInt(Math.floor(new Date(subject.birthDate).getTime() / 1000)),
      nationalId: BigInt(subject.nationalId),
      issuer: new Uint8Array(Buffer.from(payload.iss.padEnd(86, ' '))),
      ownerPk: {
        x: BigInt(privateState.ownerPK.x),
        y: BigInt(privateState.ownerPK.y)
      }
    };

    console.log('Resolved Credential:', {
      ...credential,
      ownerPk: {
        x: credential.ownerPk.x.toString(),
        y: credential.ownerPk.y.toString()
      }
    });

    return [privateState, credential];
  }

};
