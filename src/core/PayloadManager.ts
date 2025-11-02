import { v4 as uuidv4 } from 'uuid';
import { XSS_DETECT_BASE_IDENTIFIER } from '../config/constants';

export type XssPayload = {
  id: string;
  content: string;
  type: 'basic' | 'encoded' | 'obfuscated';
  purpose: 'reflected' | 'stored';
};

export class PayloadManager {
  private generatedPayloads: XssPayload[] = [];

  private generateUniqueId(): string {
    return `${XSS_DETECT_BASE_IDENTIFIER}${uuidv4().slice(0, 8)}`;
  }

  // 修复方法名：添加generatePayloadByLevel方法
  generatePayloadByLevel(level: 'LOW' | 'MEDIUM' | 'HIGH'): string {
    const payloads = this.generatePayloadsByLevel(level, 'reflected');
    return payloads[0]?.content || '';
  }

  generatePayloadsByLevel(level: 'LOW' | 'MEDIUM' | 'HIGH', purpose: 'reflected' | 'stored'): XssPayload[] {
    this.generatedPayloads = [];
    this.generatedPayloads.push(this.generateBasicPayload(purpose));
    if (level === 'MEDIUM' || level === 'HIGH') {
      this.generatedPayloads.push(this.generateEncodedPayload(purpose));
    }
    if (level === 'HIGH') {
      this.generatedPayloads.push(this.generateObfuscatedPayload(purpose));
    }
    return this.generatedPayloads;
  }

  getGeneratedPayloads(): XssPayload[] {
    return [...this.generatedPayloads];
  }

  private generateBasicPayload(purpose: 'reflected' | 'stored'): XssPayload {
    return {
      id: this.generateUniqueId(),
      content: `<script>alert('XSS_${purpose.toUpperCase()}')</script>`,
      type: 'basic',
      purpose
    };
  }

  private generateEncodedPayload(purpose: 'reflected' | 'stored'): XssPayload {
    return {
      id: this.generateUniqueId(),
      content: `&lt;script&gt;alert('XSS_${purpose.toUpperCase()}')&lt;/script&gt;`,
      type: 'encoded',
      purpose
    };
  }

  private generateObfuscatedPayload(purpose: 'reflected' | 'stored'): XssPayload {
    return {
      id: this.generateUniqueId(),
      content: `javascript:alert('XSS_${purpose.toUpperCase()}')`,
      type: 'obfuscated',
      purpose
    };
  }
}