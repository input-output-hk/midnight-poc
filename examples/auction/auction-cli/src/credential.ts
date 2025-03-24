
import SDK from "@hyperledger/identus-sdk";
import { sha512 } from '@noble/hashes/sha512';
import InMemory from '@pluto-encrypted/inmemory';
import { type Logger } from 'pino';
import { Config } from "./config";


export function createDIDResolver(cfg: Config, logger: Logger) {
    return class implements SDK.Domain.DIDResolver {
        method = "prism";

        async resolve(didString: string) {
            const url = `${cfg.issuerBaseUrl}/cloud-agent/dids/${didString}`;

            const response = await fetch(url, {
                method: "GET",
                mode: "cors",
                credentials: "omit"
            });

            if (!response.ok) {
                throw new Error('Failed to fetch data');
            }

            const data = await response.json();
            const didDocument = data.didDocument;

            const servicesProperty = new SDK.Domain.Services(didDocument.service);
            const verificationMethodsProperty = new SDK.Domain.VerificationMethods(didDocument.verificationMethod);
            const coreProperties = [];
            const authenticate = [];
            const assertion = [];

            for (const verificationMethod of didDocument.verificationMethod) {
                const isAssertion = didDocument.assertionMethod.find((method: any) => method === verificationMethod.id);
                if (isAssertion) {
                    assertion.push(new SDK.Domain.AssertionMethod([isAssertion], [verificationMethod]));
                }
                const isAuthentication = didDocument.authentication.find((method: any) => method === verificationMethod.id);
                if (isAuthentication) {
                    authenticate.push(new SDK.Domain.Authentication([isAuthentication], [verificationMethod]));
                }
            }

            coreProperties.push(...authenticate);
            coreProperties.push(servicesProperty);
            coreProperties.push(verificationMethodsProperty);

            const resolved = new SDK.Domain.DIDDocument(
                SDK.Domain.DID.fromString(didString),
                coreProperties
            );

            return resolved;
        }
    };
}

function base64UrlDecode(str: string): Buffer {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    return Buffer.from(base64 + padding, 'base64');
}

export async function getCredential(config: Config, logger: Logger): Promise<SDK.Domain.Credential> {
    return new Promise(async (resolve, reject) => {
        const registerPrismDid = await fetch(`${config.issuerBaseUrl}/cloud-agent/did-registrar/dids`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                "documentTemplate": {
                    "publicKeys": [
                        {
                            "id": "issue-1",
                            "purpose": "assertionMethod",
                            "curve": "secp256k1"
                        }
                    ],
                    "services": []
                }
            })
        });
        const prismDidResponse = await registerPrismDid.json();
        console.log('Prism DID created:', { longFormDid: prismDidResponse.longFormDid });

        const publishPrismDid = await fetch(`${config.issuerBaseUrl}/cloud-agent/did-registrar/dids/${prismDidResponse.longFormDid}/publications`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const publishResponse = await publishPrismDid.json();
        console.log('DID Published:', { operation: publishResponse.scheduledOperation });


        const createCredentialSchema = await fetch(`${config.issuerBaseUrl}/cloud-agent/schema-registry/schemas`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                "name": "driving-license",
                "version": "2.0.0",
                "description": "Driving License Schema",
                "type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
                "author": `${publishResponse.scheduledOperation?.didRef}`,
                "tags": [
                    "driving",
                    "license"
                ],
                "schema": {
                    "$id": "https://example.com/driving-license-1.0.0",
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "description": "National Id",
                    "type": "object",
                    "properties": {
                        "givenName": {
                            "type": "string"
                        },
                        "familyName": {
                            "type": "string"
                        },
                        "birthDate": {
                            "type": "string",
                            "format": "date"
                        },
                        "nationalId": {
                            "type": "string"
                        },
                        "publicKeyJwk": {
                            "type": "object",
                            "properties": {
                                "crv": {
                                    "type": "string"
                                },
                                "x": {
                                    "type": "string"
                                },
                                "y": {
                                    "type": "string"
                                },
                                "kty": {
                                    "type": "string"
                                }
                            }
                        }
                    },
                    "required": [
                        "familyName",
                        "birthDate",
                        "nationalId",
                        "givenName"
                    ],
                    "additionalProperties": true
                }
            })
        });
        const schemaResponse = await createCredentialSchema.json();
        console.log('Schema Created:', { schemaId: schemaResponse.id });

        const getMediatorDid = await fetch(`${config.mediatorBaseUrl}/did`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json"
            }
        });
        const mediatorDID = SDK.Domain.DID.fromString(await getMediatorDid.text());
        console.log('Mediator DID:', {
            did: mediatorDID
        });

        const hashedPassword = sha512("123456")
        const apollo = new SDK.Apollo();
        const store = new SDK.Store({
            name: "test",
            storage: InMemory as any,
            password: Buffer.from(hashedPassword).toString("hex")
        });
        const defaultSeed = apollo.createRandomSeed().seed // Random or custom seed u want to create
        const ShortFormDIDResolverSample = createDIDResolver(config, logger);
        const extraResolvers = [
            ShortFormDIDResolverSample
        ];

        const castor = new SDK.Castor(apollo, extraResolvers)
        const agent = await SDK.Agent.initialize({
            apollo,
            castor,
            mediatorDID,
            pluto: new SDK.Pluto(store, apollo),
            seed: defaultSeed
        });

        let credential;
        let presentationId;
        agent.addListener(SDK.ListenerKey.MESSAGE, async (messages: any) => {
            for (const message of messages) {
                if (message instanceof SDK.Domain.Message) {
                    if (message.piuri === SDK.ProtocolType.DidcommOfferCredential) {
                        /** 
                         * DIDComm Offer Credential Message
                         * Specification: https://didcomm.org/issue-credential/3.0/offer-credential
                         * Description: The credential offer contains a preview of the SDJWT credential and would inform
                         * you on what fields your credential will have.
                         * Offers must be manually accepted, and this is done by creating a Credential Request and sending it to the Cloud Agent
                         */
                        console.log('Credential Offer:', message);
                        const credentialOffer = SDK.OfferCredential.fromMessage(message);
                        const requestCredential = await agent.prepareRequestCredentialWithIssuer(credentialOffer);
                        const requestMessage = requestCredential.makeMessage()
                        await agent.sendMessage(requestMessage);
                    } else if (message.piuri === SDK.ProtocolType.DidcommIssueCredential) {
                        /** 
                         * DIDComm Issue Credential Message
                         * Specification: https://didcomm.org/issue-credential/3.0/issue-credential
                         * Description: This is the Issued Credential which gets stored inside the Identus Storage for later use.
                         */
                        console.log('Credential Issue:', message);
                        const attachment = message.attachments.at(0)
                        if (attachment) {
                            const encodedCompactJWT = attachment.payload;
                            credential = SDK.JWTCredential.fromJWS(encodedCompactJWT);
                            return resolve(credential)
                        }
                    }
                }
            }
        });

        await agent.start()
        const credentialOfferRequestBody = {
            "schemaId": `${config.issuerBaseUrl}/cloud-agent/schema-registry/schemas/${schemaResponse.guid}`,
            "goalCode": "issue-vc",
            "goal": "To Issue a Driving License Credential",
            "issuingDID": publishResponse.scheduledOperation?.didRef,
            "validityPeriod": 3600,
            "automaticIssuance": true,
            "credentialFormat": "JWT",
            "claims": {
                "givenName": "Alice",
                "familyName": "Wonderland",
                "birthDate": "2000-11-13",
                "nationalId": "12345",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "x": "OHG91xME-hEPIQXvoffHNRZ1Xno541wSJE2GFt60dGU",
                    "y": "21FT0Eb66z4mRBhexa4sFoznR28SqkQ3-WgF4zJQ3fU",
                    "kty": "EC"
                }
            }
        }
        console.log('Credential Offer Request Body*************:', JSON.stringify(credentialOfferRequestBody, null, 2));

        const getCredentialOffer = await fetch(`${config.issuerBaseUrl}/cloud-agent/issue-credentials/credential-offers/invitation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(credentialOfferRequestBody)
        });


        const credentialOfferResponse = await getCredentialOffer.json();
        console.log('Credential Offer:', { invitationUrl: credentialOfferResponse.invitation.invitationUrl });
        const parsed = await agent.parseOOBInvitation(new URL(credentialOfferResponse.invitation.invitationUrl));
        await agent.acceptInvitation(parsed, 'SampleCredentialOfferOOB');
    })
}