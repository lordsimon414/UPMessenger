export interface PullEnvelope {
  message_id: string;
  sender_device_id: string;
  ciphertext_base64: string;
  created_at: number;
  expires_at: number;
  protocol_version: number;
}

export class UpmApi {
  constructor(private readonly baseUrl: string) {}

  async pull(token: string, deviceId: string): Promise<PullEnvelope[]> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/v1/messages/pull?device_id=${encodeURIComponent(deviceId)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(`UPM pull failed: ${response.status}`);
    const body = await response.json() as { envelopes: PullEnvelope[] };
    return body.envelopes;
  }
}
