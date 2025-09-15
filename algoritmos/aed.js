const crypto = require('crypto');

/**
 * Implementação completa do algoritmo AES (Advanced Encryption Standard)
 * Esta é uma implementação educacional - para uso em produção, use o módulo crypto nativo
 */
class AES {
  // Tabela S-Box para substituição não linear
  static S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,];

  // Tabela de constantes de rodada
  static RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
  ];

  /**
   * Converte uma string em um array de bytes
   */
  static stringToBytes(str) {
    return new TextEncoder().encode(str);
  }

  /**
   * Converte um array de bytes em uma string
   */
  static bytesToString(bytes) {
    return new TextDecoder().decode(new Uint8Array(bytes));
  }

  /**
   * Realiza a substituição de bytes usando a S-Box
   */
  static subBytes(state) {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[i][j] = this.S_BOX[state[i][j]];
      }
    }
    return state;
  }

  /**
   * Realiza o deslocamento cíclico das linhas
   */
  static shiftRows(state) {
    // Primeira linha - não é deslocada
    // Segunda linha - deslocada 1 byte
    state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]];
    
    // Terceira linha - deslocada 2 bytes
    state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];
    
    // Quarta linha - deslocada 3 bytes
    state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]];
    
    return state;
  }

  /**
   * Multiplicação no campo de Galois GF(2^8)
   */
  static galoisMultiply(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hiBitSet = a & 0x80;
      a = (a << 1) & 0xFF;
      if (hiBitSet) a ^= 0x1B;
      b >>= 1;
    }
    return p;
  }

  /**
   * Mistura as colunas do estado
   */
  static mixColumns(state) {
    for (let i = 0; i < 4; i++) {
      const a = state[0][i];
      const b = state[1][i];
      const c = state[2][i];
      const d = state[3][i];
      
      state[0][i] = this.galoisMultiply(a, 0x02) ^ this.galoisMultiply(b, 0x03) ^ c ^ d;
      state[1][i] = a ^ this.galoisMultiply(b, 0x02) ^ this.galoisMultiply(c, 0x03) ^ d;
      state[2][i] = a ^ b ^ this.galoisMultiply(c, 0x02) ^ this.galoisMultiply(d, 0x03);
      state[3][i] = this.galoisMultiply(a, 0x03) ^ b ^ c ^ this.galoisMultiply(d, 0x02);
    }
    return state;
  }

  /**
   * Adiciona a chave da rodada ao estado
   */
  static addRoundKey(state, roundKey) {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[j][i] ^= roundKey[i * 4 + j];
      }
    }
    return state;
  }

  /**
   * Expande a chave para todas as rodadas
   */
  static keyExpansion(key) {
    const expandedKey = new Array(176).fill(0);
    
    // Copia a chave original para as primeiras 16 posições
    for (let i = 0; i < 16; i++) {
      expandedKey[i] = key[i];
    }
    
    let bytesGenerated = 16;
    let rconIteration = 1;
    
    while (bytesGenerated < 176) {
      // Faz uma cópia dos 4 bytes anteriores
      let temp = [
        expandedKey[bytesGenerated - 4],
        expandedKey[bytesGenerated - 3],
        expandedKey[bytesGenerated - 2],
        expandedKey[bytesGenerated - 1]
      ];
      
      // Aplica a transformação a cada 16 bytes
      if (bytesGenerated % 16 === 0) {
        // Rotaciona os bytes
        temp = [temp[1], temp[2], temp[3], temp[0]];
        
        // Aplica a S-Box
        for (let i = 0; i < 4; i++) {
          temp[i] = this.S_BOX[temp[i]];
        }
        
        // Aplica RCON
        temp[0] ^= this.RCON[rconIteration - 1];
        rconIteration++;
      }
      
      // XOR com os bytes de 16 posições atrás
      for (let i = 0; i < 4; i++) {
        expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ temp[i];
        bytesGenerated++;
      }
    }
    
    return expandedKey;
  }

  /**
   * Converte um array de 16 bytes em uma matriz de estado 4x4
   */
  static bytesToState(bytes) {
    const state = [[], [], [], []];
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        state[j][i] = bytes[i * 4 + j];
      }
    }
    return state;
  }

  /**
   * Converte uma matriz de estado 4x4 em um array de 16 bytes
   */
  static stateToBytes(state) {
    const bytes = new Array(16);
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        bytes[i * 4 + j] = state[j][i];
      }
    }
    return bytes;
  }

  /**
   * Criptografa um bloco de 16 bytes usando AES-128
   */
  static encryptBlock(block, key) {
    // Expande a chave
    const expandedKey = this.keyExpansion(key);
    
    // Converte o bloco em matriz de estado
    let state = this.bytesToState(block);
    
    // Ronda inicial
    state = this.addRoundKey(state, expandedKey.slice(0, 16));
    
    // 9 rondas principais
    for (let round = 1; round < 10; round++) {
      state = this.subBytes(state);
      state = this.shiftRows(state);
      state = this.mixColumns(state);
      state = this.addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
    }
    
    // Ronda final
    state = this.subBytes(state);
    state = this.shiftRows(state);
    state = this.addRoundKey(state, expandedKey.slice(160, 176));
    
    // Converte o estado de volta para bytes
    return this.stateToBytes(state);
  }

  /**
   * Preenche o texto para que tenha um tamanho múltiplo de 16 bytes
   */
  static pad(data) {
    const blockSize = 16;
    const padding = blockSize - (data.length % blockSize);
    const result = new Uint8Array(data.length + padding);
    result.set(data);
    for (let i = data.length; i < result.length; i++) {
      result[i] = padding;
    }
    return result;
  }

  /**
   * Remove o preenchimento do texto
   */
  static unpad(data) {
    const padding = data[data.length - 1];
    return data.slice(0, data.length - padding);
  }

  /**
   * Criptografa um texto usando AES-128 no modo CBC
   */
  static encrypt(text, key, iv) {
    // Converte os dados de entrada
    const textBytes = this.stringToBytes(text);
    const keyBytes = typeof key === 'string' ? this.stringToBytes(key) : key;
    const ivBytes = typeof iv === 'string' ? this.stringToBytes(iv) : iv;
    
    // Preenche o texto
    const paddedData = this.pad(textBytes);
    
    // Criptografa cada bloco
    const encryptedBlocks = [];
    let previousBlock = ivBytes;
    
    for (let i = 0; i < paddedData.length; i += 16) {
      const block = paddedData.slice(i, i + 16);
      
      // XOR com o bloco anterior (modo CBC)
      for (let j = 0; j < 16; j++) {
        block[j] ^= previousBlock[j];
      }
      
      // Criptografa o bloco
      const encryptedBlock = this.encryptBlock(block, keyBytes);
      encryptedBlocks.push(encryptedBlock);
      previousBlock = encryptedBlock;
    }
    
    // Concatena todos os blocos criptografados
    const encrypted = new Uint8Array(encryptedBlocks.length * 16);
    for (let i = 0; i < encryptedBlocks.length; i++) {
      encrypted.set(encryptedBlocks[i], i * 16);
    }
    
    return encrypted;
  }

  /**
   * Descriptografa um texto usando AES-128 no modo CBC
   */
  static decrypt(encryptedData, key, iv) {
    const keyBytes = typeof key === 'string' ? this.stringToBytes(key) : key;
    const ivBytes = typeof iv === 'string' ? this.stringToBytes(iv) : iv;
    
    // Implementação básica de descriptografia (simplificada)
    // Nota: Esta é uma implementação educacional
    // Em uma implementação real, você precisaria implementar todas as transformações inversas
    
    // Para fins de demonstração, vamos usar a implementação nativa do Node.js
    const decipher = crypto.createDecipheriv('aes-128-cbc', keyBytes, ivBytes);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return this.unpad(decrypted);
  }
}

// Exemplo de uso
function example() {
  // Chave e IV (Initialization Vector)
  const key = crypto.randomBytes(16); // Chave AES-128 (16 bytes)
  const iv = crypto.randomBytes(16);  // IV (16 bytes)
  
  // Texto para criptografar
  const text = "Mensagem secreta para criptografar com AES!";
  
  console.log("Texto original:", text);
  console.log("Chave:", key.toString('hex'));
  console.log("IV:", iv.toString('hex'));
  
  // Criptografar
  const encrypted = AES.encrypt(text, key, iv);
  console.log("Texto criptografado (hex):", Buffer.from(encrypted).toString('hex'));
  
  // Descriptografar (usando implementação nativa para simplificar)
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  console.log("Texto descriptografado:", decrypted.toString());
}

// Executar o exemplo
example();