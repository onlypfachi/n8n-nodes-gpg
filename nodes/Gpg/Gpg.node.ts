import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';

import { BINARY_ENCODING } from 'n8n-workflow';

import type { Readable } from 'stream';

import * as openpgp from 'openpgp';

export class Gpg implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'GPG',

		name: 'gpg',
		icon: 'file:gpg.svg',
		group: ['input'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Use GPG to encrypt or decrypt data',
		defaults: {
			name: 'GPG',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{

				name: 'gpgKeyApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Encrypt',
						value: 'encrypt',
					},
					{
						name: 'Decrypt',
						value: 'decrypt',
					},
				],
				default: 'encrypt',
				description: 'Which operation to use?',
			},
			{
				displayName: 'Type',
				name: 'type',
				type: 'options',
				options: [
					{
						name: 'File',
						value: 'file',
					},
					{
						name: 'String',
						value: 'string',
					},
				],
				default: 'file',
			},
			{
				displayName: 'Text',
				name: 'text',
				type: 'string',
				default: '',
				displayOptions: {
					show: {
						type: ['string'],
					},
				},
			},

			{
				displayName: 'Binary Property',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				displayOptions: {
					show: {
						type: ['file'],
					},
				},
			},
			{
				displayName: 'Output Property',
				name: 'outputBinaryPropertyName',
				type: 'string',
				default: '',
				displayOptions: {
					show: {
						type: ['file'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const operation = this.getNodeParameter('operation', 0);
		const credentials = await this.getCredentials('gpgKeyApi');
		let responseData;

		for (let i = 0; i < items.length; i++) {
			const dataType = this.getNodeParameter('type', i) as string;
			try {
				if (operation === 'encrypt') {
					const publicKey = await openpgp.readKey({ armoredKey: credentials.key as string });
					if (dataType === 'string') {
						const data = this.getNodeParameter('text', i) as string;
						const encrypted = await openpgp.encrypt({
							message: await openpgp.createMessage({ text: data }),
							encryptionKeys: publicKey,
						});
						responseData = [{ encrypted }];
					}

					if (dataType === 'file') {
						const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i);
						const outputBinaryPropertyName = this.getNodeParameter(
							'outputBinaryPropertyName',
							i,
							'encrypted',
						) as string;
						const binaryData = this.helpers.assertBinaryData(i, binaryPropertyName);

						let pgpData : Readable | Buffer;
						if (binaryData.id) {
							pgpData = await this.helpers.getBinaryStream(binaryData.id);
						} else {
							pgpData = Buffer.from(binaryData.data, BINARY_ENCODING);
						}

						const encrypted = await openpgp.encrypt({
							message: await openpgp.createMessage({ binary: pgpData }),
							encryptionKeys: publicKey,
							format: 'binary',
						});

						const buffer = Buffer.from(encrypted as Uint8Array);

						items[i].binary![outputBinaryPropertyName] = await this.helpers.prepareBinaryData(
							buffer,
						);
						items[i].binary![outputBinaryPropertyName].fileName = `${binaryData.fileName}.gpg`;
						items[i].binary![outputBinaryPropertyName].fileExtension = 'gpg';
						items[i].binary![outputBinaryPropertyName].mimeType = 'application/pgp-encrypted';

						responseData = this.helpers.constructExecutionMetaData(
							this.helpers.returnJsonArray(items[i]),
							{ itemData: { item: i } },
						);
					}
				}

				if (operation === 'decrypt') {
					const privateKey = await openpgp.decryptKey({
						privateKey: await openpgp.readPrivateKey({ armoredKey: credentials.key as string }),
						passphrase: credentials.passphrase as string,
					});

					// Decrypt if data type is a string
					if (dataType === 'string') {
						const message = await openpgp.readMessage({
							armoredMessage: this.getNodeParameter('text', i) as string,
						});

						const { data: decrypted } = await openpgp.decrypt({
							message,
							decryptionKeys: privateKey, config: { allowInsecureDecryptionWithSigningKeys: true }
						});
						responseData = [{ decrypted }];
					}

					// Dycrypt if data type is file
					if (dataType === 'file') {
						const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i);
						const outputBinaryPropertyName = this.getNodeParameter(
							'outputBinaryPropertyName',
							i,
							'decrypted',
						) as string;
						const binaryData = this.helpers.assertBinaryData(i, binaryPropertyName);

						let pgpData: Buffer | Readable;
						if (binaryData.id) {
							pgpData = await this.helpers.getBinaryStream(binaryData.id);
						} else {
							pgpData = Buffer.from(binaryData.data, BINARY_ENCODING);
						}

						const encryptedMessage = await openpgp.readMessage({
							binaryMessage: pgpData,
						});
						const { data: decrypted } = await openpgp.decrypt({
							message: encryptedMessage,
							decryptionKeys: privateKey,
							format: 'binary',
							config: { allowInsecureDecryptionWithSigningKeys: true }
						});

						const buffer = Buffer.from(decrypted as Uint8Array);

						items[i].binary![outputBinaryPropertyName] = await this.helpers.prepareBinaryData(
							buffer,
						);
						items[i].binary![outputBinaryPropertyName].fileName = `${binaryData.fileName}`;

						responseData = this.helpers.constructExecutionMetaData(
							this.helpers.returnJsonArray(items[i]),
							{ itemData: { item: i } },
						);
					}
				}
				const executionData = this.helpers.constructExecutionMetaData(
					this.helpers.returnJsonArray(responseData as IDataObject[]),
					{ itemData: { item: i } },
				);
				returnData.push(...executionData);
			} catch (error) {
				if (this.continueOnFail()) {
					const executionErrorData = this.helpers.constructExecutionMetaData(
						this.helpers.returnJsonArray({ error: error.message }),
						{ itemData: { item: i } },
					);
					returnData.push(...executionErrorData);
					continue;
				}
				throw error;
			}
		}

		return this.prepareOutputData(returnData);
	}
}
