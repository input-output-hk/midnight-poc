
/// <reference types="@hyperledger/identus-sdk" />
import SDK from "@hyperledger/identus-sdk";
import {
    sha512
} from '@noble/hashes/sha512';

import InMemory from '@pluto-encrypted/inmemory';


class ShortFormDIDResolverSample {
    method = "prism";

    async resolve(didString) {
        const url = "http://192.168.1.86:8085/cloud-agent/dids/" + didString;
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
            const registerPrismDid = await fetch(`http://192.168.1.86:8085/cloud-agent/did-registrar/dids`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    "documentTemplate": {
                        "publicKeys": [
                            {
                                "id": "auth-1",
                                "purpose": "authentication",
                                "curve": "secp256k1"
                            },
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

            const publishPrismDid = await fetch(`http://192.168.1.86:8085/cloud-agent/did-registrar/dids/${prismDidResponse.longFormDid}/publications`, {
                method: "POST",
                headers: { "Content-Type": "application/json" }
            });
            const publishResponse = await publishPrismDid.json();
            console.log('DID Published:', { operation: publishResponse.scheduledOperation });

            const createCredentialSchema = await fetch("http://192.168.1.86:8085/cloud-agent/schema-registry/schemas", {
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

            const getMediatorDid = await fetch("http://192.168.1.86:8080/did", {
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
                             * Description: The credential offer contains a preview of the JWT credential and would inform
                             * you on what fields your credential will have.
                             * Offers must be manually accepted, and this is done by creating a Credential Request and sending it to the Cloud Agent
                             */
                            console.log('Credential Offer:', message);
                            const credentialOffer = SDK.OfferCredential.fromMessage(message);
                            const requestCredential = await agent.prepareRequestCredentialWithIssuer(credentialOffer);

                            // const holderPrismDIDs = await agent.pluto.getAllPrismDIDs();
                            // console.log('+++++++++ holderPrismDIDs:', { dids: holderPrismDIDs });
                            // const holderPrismDID = holderPrismDIDs[0];
                            // console.log('+++++++ holderPrismDID:', { did: holderPrismDID.did.uuid });
                            // const didDocument = await agent.castor.resolveDID(holderPrismDID.did.uuid)
                            // console.log('+++++++ didDocument:', { didDocument: didDocument });
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
            console.log('Agent started', agent.apollo);
            const credentialOfferRequestBody = {
                "schemaId": `http://192.168.1.86:8085/cloud-agent/schema-registry/schemas/${schemaResponse.guid}`,
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
                        "x": "AIK7wWytffTGGuy_DiBs3dYn26qzvWYeCQpcocLXLAs",
                        "y": "WYdiN4nkWRcDK044UBCIJCdktqKn0OaVrnYSKeC3Tfg",
                        "kty": "EC"
                    }
                }
            }
            const credentialOfferRequestBody1 = {
                "schemaId": `http://192.168.1.86:8085/cloud-agent/schema-registry/schemas/${schemaResponse.guid}`,
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
                    "dateOfIssuance": "2020-11-13T20:20:39+00:00"
                }
            };
            console.log('Credential Offer Request Body:', JSON.stringify(credentialOfferRequestBody, null, 2));
            const getCredentialOffer = await fetch("http://192.168.1.86:8085/cloud-agent/issue-credentials/credential-offers/invitation", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(credentialOfferRequestBody)
            });



            console.log('Credential******* schemaResponse Offer:', { schemaId: schemaResponse.guid });


            const credentialOfferResponse = await getCredentialOffer.json();
            console.log('Credential Offer:', { invitationUrl: credentialOfferResponse.invitation.invitationUrl });
            const parsed = await agent.parseOOBInvitation(new URL(credentialOfferResponse.invitation.invitationUrl));
            await agent.acceptInvitation(parsed, 'SampleCredentialOfferOOB');

        })
    }
    try {
        console.log("Starting credential issuance process...");
        const credential = await getCredential();
        console.log("Credential received successfully:", credential);
    } catch (error) {
        console.error("Error getting credential:", error);
    }

})();
