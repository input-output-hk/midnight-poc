





/// <reference types="@hyperledger/identus-edge-agent-sdk" />
//Add this packages on top
import SDK from "@hyperledger/identus-edge-agent-sdk";
import {
    sha512
} from '@noble/hashes/sha512'

import InMemory from '@pluto-encrypted/inmemory';


import {  WalletBuilder } from '@midnight-ntwrk/wallet';
import { NetworkId, setNetworkId, getZswapNetworkId } from '@midnight-ntwrk/midnight-js-network-id';



class StandaloneConfig {
    privateStateStoreName = 'auction-private-state';
    logDir = "./logs"; //path.resolve(currentDir, '..', 'logs', 'standalone', `${new Date().toISOString()}.log`);
    zkConfigPath = "./zkpath"; //path.resolve(currentDir, '..', '..', 'contract', 'dist', 'managed', 'auction');
    indexer = 'http://127.0.0.1:8088/api/v1/graphql';
    indexerWS = 'ws://127.0.0.1:8088/api/v1/graphql/ws';
    node = 'http://127.0.0.1:9944';
    proofServer = 'http://127.0.0.1:6300';

    setNetworkId() {
        setNetworkId(NetworkId.Undeployed);
    }
}


class ShortFormDIDResolverSample {
    method = "prism";

    async resolve(didString) {
        const url = "http://localhost:8085/cloud-agent/dids/" + didString;
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
            const isAssertion = didDocument.assertionMethod.find(method => method === verificationMethod.id);
            if (isAssertion) {
                assertion.push(new SDK.Domain.AssertionMethod([isAssertion], [verificationMethod]));
            }
            const isAuthentication = didDocument.authentication.find(method => method === verificationMethod.id);
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
}

async function verifyCondition(callback) {
    try {
        const start = Date.now()
        await new Promise(async (resolve, reject) => {
            const interval = setInterval(async () => {
                let result = await callback()
                if (result) {
                    clearInterval(interval)
                    resolve("")
                }
                if (Date.now() - start > 60 * 1000) {
                    reject("timeout")
                }
            }, 1000)
        })
        return true
    } catch (e) {
        return false
    }
};


(async () => {

    async function getCredential() {
        return new Promise(async (resolve, reject) => {
            const registerPrismDid = await fetch(`http://localhost:8085/cloud-agent/did-registrar/dids`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    "documentTemplate": {
                        "publicKeys": [
                        {
                          "id": "auth-1",
                          "purpose": "authentication",
                          "curve":"secp256k1"
                        },
                        {
                          "id": "issue-1",
                          "purpose": "assertionMethod",
                          "curve":"secp256k1"
                        }
                      ],
                      "services": []
                    }
                })
            });
            const prismDidResponse = await registerPrismDid.json();
            console.log('Prism DID created:', { longFormDid: prismDidResponse.longFormDid });
        
            const publishPrismDid = await fetch(`http://localhost:8085/cloud-agent/did-registrar/dids/${prismDidResponse.longFormDid}/publications`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            });
            const publishResponse = await publishPrismDid.json();
            console.log('DID Published:', { operation: publishResponse.scheduledOperation });
        
            const createCredentialSchema = await fetch("http://localhost:8085/cloud-agent/schema-registry/schemas", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    "name": "medical-prescription-schema-2b754046-32c6-42e0-b587-b28013422778",
                    "version": "2.0.0",
                    "description": "Medical Prescription Schema",
                    "type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
                    "author": `${publishResponse.scheduledOperation?.didRef}`,
                    "tags": [
                        "driving",
                        "license"
                    ],
                    "schema": {
                        "$id": "https://example.com/medical-prescription-1.0.0",
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "description": "Medical Prescription ",
                        "type": "object",
                        "properties": {
                            "patientId": {
                                "type": "string",
                            },
                            "patientName": {
                                "type": "string"
                            },
                            "patientFamilyName": {
                                "type": "string"
                            },
                            "prescriptionId": {
                                "type": "string"
                            },
                            "dateOfIssuance": {
                                "type": "string",
                                "format": "date-time"
                            }
                        },
                        "required": [
                            "patientId",
                            "patientName",
                            "patientFamilyName",
                            "prescriptionId",
                            "dateOfIssuance"
                        ],
                        "additionalProperties": false
                    }
                })
            });
            const schemaResponse = await createCredentialSchema.json();
            console.log('Schema Created:', { schemaId: schemaResponse.id });
        
            const getMediatorDid = await fetch("http://localhost:8080/did", {
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
                storage: InMemory,
                password: Buffer.from(hashedPassword).toString("hex")
            });
            const defaultSeed = apollo.createRandomSeed().seed // Random or custom seed u want to create
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
            agent.addListener(SDK.ListenerKey.MESSAGE, async (messages) => {
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
                                const encodedCompactSDJWT = attachment.payload;
                                credential = SDK.SDJWTCredential.fromJWS(encodedCompactSDJWT);
                                return resolve(credential)
                            }
                        } 
                    }
                }
            });
        
            await agent.start()
        
            const getCredentialOffer = await fetch("http://localhost:8085/cloud-agent/issue-credentials/credential-offers/invitation", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    "goalCode": "issue-vc",
                    "goal": "To Issue a Medical Prescription Credential",
                    "issuingDID": publishResponse.scheduledOperation?.didRef,
                    "validityPeriod": 3600,
                    "automaticIssuance": true,
                    "credentialFormat": "JWT",
                    "claims": {
                        "patientId": "#d4aab32e1",
                        "patientName": "Alice",
                        "patientFamilyName": "Wonderland",
                        "prescriptionId": "42344211134",
                        "dateOfBirth": "2020-11-13T20:20:39+00:00"
                    }
                })
            });
            const credentialOfferResponse = await getCredentialOffer.json();
            console.log('Credential Offer:', { invitationUrl: credentialOfferResponse.invitation.invitationUrl });
            const parsed = await agent.parseOOBInvitation(new URL(credentialOfferResponse.invitation.invitationUrl));
            await agent.acceptInvitation(parsed, 'SampleCredentialOfferOOB');
        })
    }
    
})();