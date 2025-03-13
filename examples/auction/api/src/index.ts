/**
 * Provides types and utilities for working with bulletin board contracts.
 *
 * @packageDocumentation
 */

import SDK from "@hyperledger/identus-edge-agent-sdk";
import {
  type AuctionPrivateState,
  Contract,
  createAuctionPrivateState,
  ledger,
  parseJwtPayload,
  pureCircuits,
  STATE,
  VCPayload,
  witnesses,
} from '@midnight-ntwrk/auction-contract';
import { type ContractAddress } from '@midnight-ntwrk/compact-runtime';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { toHex } from '@midnight-ntwrk/midnight-js-utils';
import { type Logger } from 'pino';
import { combineLatest, from, map, type Observable, tap } from 'rxjs';
import type { AuctionContract, AuctionDerivedState, AuctionProviders, DeployedAuctionContract } from './common-types.js';
import * as utils from './utils/index.js';
import { verifyJWT } from './utils/jwt-verification.js';
import {
    sha512
} from '@noble/hashes/sha512'
import InMemory from '@pluto-encrypted/inmemory';

/** @internal */
const auctionContractInstance: AuctionContract = new Contract(witnesses);

/**
 * An API for a deployed bulletin board.
 */
export interface DeployedAuctionAPI {
  readonly deployedContractAddress: ContractAddress;
  readonly state$: Observable<AuctionDerivedState>;

  placeBid: (bid: bigint) => Promise<void>;
  concludeAuction: () => Promise<void>;
}

/**
 * Provides an implementation of {@link DeployedAuctionAPI} by adapting a deployed bulletin board
 * contract.
 *
 * @remarks
 * The `AuctionPrivateState` is managed at the DApp level by a private state provider. As such, this
 * private state is shared between all instances of {@link AuctionAPI}, and their underlying deployed
 * contracts. The private state defines a `'secretKey'` property that effectively identifies the current
 * user, and is used to determine if the current user is the poster of the message as the observable
 * contract state changes.
 *
 * In the future, Midnight.js will provide a private state provider that supports private state storage
 * keyed by contract address. This will remove the current workaround of sharing private state across
 * the deployed bulletin board contracts, and allows for a unique secret key to be generated for each bulletin
 * board that the user interacts with.
 */
// TODO: Update AuctionAPI to use contract level private state storage.
export class AuctionAPI implements DeployedAuctionAPI {
  /** @internal */
  private constructor(
    public readonly deployedContract: DeployedAuctionContract,
    providers: AuctionProviders,
    private readonly logger?: Logger,
    private readonly credential?: SDK.Domain.Credential
  ) {
    this.deployedContractAddress = deployedContract.deployTxData.public.contractAddress;
    this.state$ = combineLatest(
      [
        // Combine public (ledger) state with...
        providers.publicDataProvider.contractStateObservable(this.deployedContractAddress, { type: 'latest' }).pipe(
          map((contractState) => ledger(contractState.data)),
          tap((ledgerState) =>
            logger?.trace({
              ledgerStateChanged: {
                ledgerState: {
                  ...ledgerState,
                  state: ledgerState.auctionState === STATE.concluded ? 'concluded' : 'opened',
                  seller: toHex(ledgerState.itemSeller),
                },
              },
            }),
          ),
        ),
        // ...private state...
        //    since the private state of the bulletin board application never changes, we can query the
        //    private state once and always use the same value with `combineLatest`. In applications
        //    where the private state is expected to change, we would need to make this an `Observable`.
        from(providers.privateStateProvider.get('auctionPrivateState') as Promise<AuctionPrivateState>),
      ],
      // ...and combine them to produce the required derived state.
      (ledgerState, privateState) => {
        const hashedSecretKey = pureCircuits.public_key(
          privateState.secretKey,
        );

        return {
          auction_state: ledgerState.auctionState,
          item_description: ledgerState.itemDescription,
          minimum_bid: ledgerState.minimumBid,
          bid_increment: ledgerState.bidIncrement,
          current_bid: ledgerState.currentBid.value,
          current_bidder: ledgerState.currentBidder.value,
          reserve_price: ledgerState.reservePrice,
          item_seller: ledgerState.itemSeller,
          isSeller: toHex(ledgerState.itemSeller) === toHex(hashedSecretKey),
        };
      },
    );
  }

  /**
   * Gets the address of the current deployed contract.
   */
  readonly deployedContractAddress: ContractAddress;

  /**
   * Gets an observable stream of state changes based on the current public (ledger),
   * and private state data.
   */
  readonly state$: Observable<AuctionDerivedState>;

  /**
   * Attempts to post a given message to the bulletin board.
   *
   * @param message The message to post.
   *
   * @remarks
   * This method can fail during local circuit execution if the bulletin board is currently occupied.
   */
  async placeBid(bid: bigint): Promise<void> {
    this.logger?.info(`placing bid: ${bid}`);
    const currentTime = BigInt(Math.floor(Date.now() / 1000));
    console.log(currentTime);

    const txData =
      // EXERCISE 3: CALL THE post CIRCUIT AND SUBMIT THE TRANSACTION TO THE NETWORK
      await this.deployedContract.callTx // EXERCISE ANSWER
        .place_bid(bid, currentTime); // EXERCISE ANSWER

    this.logger?.trace({
      transactionAdded: {
        circuit: 'place_bid',
        txHash: txData.public.txHash,
        blockHeight: txData.public.blockHeight,
      },
    });
  }

  /**
   * Attempts to take down any currently posted message on the bulletin board.
   *
   * @remarks
   * This method can fail during local circuit execution if the bulletin board is currently vacant,
   * or if the currently posted message isn't owned by the poster computed from the current private
   * state.
   */
  async concludeAuction(): Promise<void> {
    this.logger?.info('concluding auction');

    const txData =
      // EXERCISE 4: CALL THE take_down CIRCUIT AND SUBMIT THE TRANSACTION TO THE NETWORK
      await this.deployedContract.callTx // EXERCISE ANSWER
        .conclude_auction(); // EXERCISE ANSWER

    this.logger?.trace({
      transactionAdded: {
        circuit: 'conclude_auction',
        txHash: txData.public.txHash,
        blockHeight: txData.public.blockHeight,
      },
    });
  }

  /**
   * Deploys a new bulletin board contract to the network.
   *
   * @param providers The bulletin board providers.
   * @param logger An optional 'pino' logger to use for logging.
   * @returns A `Promise` that resolves with a {@link AuctionAPI} instance that manages the newly deployed
   * {@link DeployedAuctionContract}; or rejects with a deployment error.
   */
  static async deploy(providers: AuctionProviders, args: [_item_description: string, _minimum_bid: bigint, _bid_increment: bigint, _reserve_price: bigint], credential: SDK.Domain.Credential, logger?: Logger): Promise<AuctionAPI> {
    logger?.info('deployContract');

    // EXERCISE 5: FILL IN THE CORRECT ARGUMENTS TO deployContract
    const deployedAuctionContract = await deployContract(providers, {
      // EXERCISE ANSWER
      privateStateKey: 'auctionPrivateState', // EXERCISE ANSWER
      contract: auctionContractInstance,
      initialPrivateState: await AuctionAPI.getPrivateState(providers, credential, logger),
      args: args
    });

    logger?.trace({
      contractDeployed: {
        finalizedDeployTxData: deployedAuctionContract.deployTxData.public,
      },
    });

    return new AuctionAPI(deployedAuctionContract, providers, logger);
  }

  /**
   * Finds an already deployed bulletin board contract on the network, and joins it.
   *
   * @param providers The bulletin board providers.
   * @param contractAddress The contract address of the deployed bulletin board contract to search for and join.
   * @param logger An optional 'pino' logger to use for logging.
   * @returns A `Promise` that resolves with a {@link AuctionAPI} instance that manages the joined
   * {@link DeployedAuctionContract}; or rejects with an error.
   */
  static async join(providers: AuctionProviders, contractAddress: ContractAddress, credential: SDK.Domain.Credential, logger?: Logger): Promise<AuctionAPI> {
    logger?.info({
      joinContract: {
        contractAddress,
      },
    });

    const deployedAuctionContract = await findDeployedContract(providers, {
      contractAddress,
      contract: auctionContractInstance,
      privateStateKey: 'auctionPrivateState',
      initialPrivateState: await AuctionAPI.getPrivateState(providers,credential, logger),
    });

    logger?.trace({
      contractJoined: {
        finalizedDeployTxData: deployedAuctionContract.deployTxData.public,
      },
    });

    return new AuctionAPI(deployedAuctionContract, providers, logger, credential);
  }

  private static async getPrivateState(providers: AuctionProviders, credential: SDK.Domain.Credential, logger?: Logger): Promise<AuctionPrivateState> {

    const jwt = credential.id;
    logger?.info(`jwt: ${jwt}`);

    const existingPrivateState = await providers.privateStateProvider.get('auctionPrivateState');
    logger?.info(`Existing 'auctionPrivateState' found: ${existingPrivateState ? 'yes' : 'no'}`);
    const jwtInfo = parseJwtPayload(utils.rawJwtString());
    const payload = jwtInfo.payload as VCPayload;
    logger?.info(`payload: ${payload}`);
    const issuerPublicKey = await utils.getIssuerPublicKeyFromDid(payload.iss, logger); // Verification key of the issuer
    const issuerPublicKeyJWK = await utils.getIssuerPublicKeyJwk(payload.iss, logger); // Verification key of the issuer

    logger?.info(`*******issuerPublicKeyJWK: ${issuerPublicKeyJWK}`);
    const isValid = await verifyCredential(utils.rawJwtString(), issuerPublicKeyJWK, logger);
    logger?.info(`*********Verification : ${isValid}`);

    const ownerPK = {
      x: BigInt(0), // TODO Get from the wallet
      y: BigInt(0) // TODO Get from the wallet
    };
    const privateState = existingPrivateState ?? createAuctionPrivateState(utils.randomBytes(32), utils.rawJwtString(), ownerPK);
    logger?.info(`Private state 'secret key': ${toHex(privateState.secretKey)}`);
    return privateState;
  }
}
async function verifyCredential(jwt: string, publicKeyJwk: SDK.Domain.PublicKeyJWK, logger?: Logger) {
  logger?.info(`*********verifyCredential : ${jwt}`);
  const result = await verifyJWT(jwt, publicKeyJwk, logger);
  if (!result.isValid) {
    logger?.info(`Verification failed: ${result.error}`);
    return false;
  }
  logger?.info(`*********verifyCredential result : ${result}`);
  return true;
}

/**
 * A namespace that represents the exports from the `'utils'` sub-package.
 *
 * @public
 */
export * as utils from './utils/index.js';

export * from './common-types.js';
