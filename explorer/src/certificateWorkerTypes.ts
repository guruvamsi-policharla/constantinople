export interface StartCertificateStreamRequest {
    readonly kind: 'start';
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

export type CertificateWorkerRequest = StartCertificateStreamRequest;

export type CertificateWorkerResponse =
    | {
          readonly kind: 'verified';
          readonly height: number;
          readonly view: string;
      }
    | {
          readonly kind: 'error';
          readonly height: number;
          readonly detail: string;
      };
