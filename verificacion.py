#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, hashlib, struct
from py_ecc.bls import G2ProofOfPossession as bls

BEACON = "http://127.0.0.1:5052"   



# PARA SIMPLESERIALIZE (SSZ) -> CHUNKS DE 32 BYTES -> HASH TREE ROOT (HTR)

ZERO_CHUNK = b"\x00"*32  # chunk nulo de 32 bytes (para padding)
def sha256(x: bytes) -> bytes: return hashlib.sha256(x).digest()  # atajo SHA-256

def next_pow2(n:int)->int:
    # Siguiente potencia de 2 >= n (necesaria para "completar" el árbol Merkle a potencia de 2)
    return 1 if n<=1 else 1<<(n-1).bit_length()

def merkleize(chunks:list[bytes])->bytes:
    # Implementación mínima de merkleización SSZ:
    # - Si no hay chunks, por convención SSZ se hashea un chunk cero.
    # - Se paddea la lista a potencia de 2 con ZERO_CHUNK.
    # - Se hace hashing par-a-par hasta quedar con 1 hash (la raíz).
    #  preguntar al profe hasta que punto es necesario hacer/entender esto.
    if not chunks: return sha256(ZERO_CHUNK)
    t = next_pow2(len(chunks))
    level = chunks + [ZERO_CHUNK]*(t-len(chunks))
    while len(level)>1:
        level = [sha256(level[i]+level[i+1]) for i in range(0,len(level),2)]
    return level[0]

def u64_chunk(x:int)->bytes:
    # Convierte un uint64 al chunk SSZ de 32B:
    # 8 bytes little-endian + 24 bytes de padding cero = 32 bytes
    return struct.pack("<Q", x)+b"\x00"*24

def b32_chunk(b:bytes)->bytes:
    # Asegura que el argumento ya sea exactamente 32B (p. ej. una raíz SSZ)
    assert len(b)==32; return b

def container_root(chunks:list[bytes])->bytes:
    # Raíz de un contenedor SSZ = merkleización de sus campos como chunks de 32B
    return merkleize(chunks)

def beacon_block_header_root(slot:int, proposer_index:int, parent_root_hex:str, state_root_hex:str, body_root_hex:str)->bytes:
    # Calcula la HashTreeRoot (HTR) del BeaconBlockHeader según SSZ.
    # Orden y tipos son críticos y deben coincidir con la spec:
    #   header = { slot(u64), proposer_index(u64), parent_root(32B), state_root(32B), body_root(32B) }
    h = lambda hx: bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
    chunks = [u64_chunk(slot), u64_chunk(proposer_index), b32_chunk(h(parent_root_hex)),
              b32_chunk(h(state_root_hex)), b32_chunk(h(body_root_hex))]
    return container_root(chunks)

def compute_fork_data_root(current_version_hex:str, genesis_validators_root_hex:str)->bytes:
    # HTR(ForkData) donde ForkData = { current_version(4B), genesis_validators_root(32B) }
    # current_version ocupa 4 bytes y se "chunkea" a 32B (4B + 28B cero).
    v = bytes.fromhex(current_version_hex[2:] if current_version_hex.startswith("0x") else current_version_hex)
    g = bytes.fromhex(genesis_validators_root_hex[2:] if genesis_validators_root_hex.startswith("0x") else genesis_validators_root_hex)
    assert len(v)==4 and len(g)==32
    return container_root([v + b"\x00"*28, g])

def compute_domain(domain_type:bytes, current_version_hex:str, genesis_validators_root_hex:str)->bytes:
    # Dominio de firmas BLS en consenso:
    # domain = domain_type(4B) || fork_data_root[:28]  -> total 32B
    # Esto amarra la firma al propósito (tipo) y a la red (via fork_data_root),
    # evitando reuso de firmas entre distintas redes/tipos.
    fork_data_root = compute_fork_data_root(current_version_hex, genesis_validators_root_hex)
    return domain_type + fork_data_root[:28]

def signing_root(object_root:bytes, domain:bytes)->bytes:
    # SigningData = { object_root(32B), domain(32B) }
    # El "mensaje" que firman/validan los validadores es HTR(SigningData)
    # y NO el objeto crudo. Esto sigue compute_signing_root de la spec.
    return container_root([object_root, domain])

# ---------------- Beacon API ----------------
def J(path:str, **params):
    # Helper HTTP GET genérico contra la Beacon API; lanza excepción si status != 2xx
    r = requests.get(f"{BEACON}{path}", params=params, timeout=10); r.raise_for_status(); return r.json()

def get_genesis():
    # /eth/v1/beacon/genesis -> devuelve el GENESIS_VALIDATORS_ROOT y genesis_time
    d = J("/eth/v1/beacon/genesis")["data"]; return d["genesis_validators_root"], d["genesis_time"]

def get_current_fork_version():
    # /eth/v1/beacon/states/{state_id}/fork -> versión de fork del estado "finalized"
    # (4 bytes hex, ej. 0x00000000, 0x01000000, etc.)
    return J("/eth/v1/beacon/states/finalized/fork")["data"]["current_version"]  # 0x........

def get_finality_update():
    # Endpoint light-client que entrega FinalityUpdate con:
    # - attested_header (beacon header atestado)
    # - sync_aggregate: bits de participantes + firma agregada BLS
    return J("/eth/v1/beacon/light_client/finality_update")["data"]

def get_validator_pubkeys(indices:list[str], state_id:str="finalized")->dict[str,str]:
    """Resuelve pubkeys para una lista de índices de validadores, en batches."""
    out: dict[str,str] = {}
    if not indices: return out
    bs = 128  # batch size para no pedir demasiados a la vez
    for i in range(0, len(indices), bs):
        batch = indices[i:i+bs]
        jj = J(f"/eth/v1/beacon/states/{state_id}/validators", id=",".join(batch))
        for it in jj.get("data", []):
            idx = str(it.get("index"))
            pub = (it.get("validator") or {}).get("pubkey")
            if idx and pub:
                out[idx] = pub
    return out

def get_sync_committee_pubkeys(period:int):
    # Obtiene las 512 pubkeys del sync committee activo para un período.
    # Un período de sync committee dura 8192 slots ≈ 256 epochs.
    # La API de sync_committees se parametriza por epoch; usamos epoch = period * 256.
    epoch = period*256
    d = J("/eth/v1/beacon/states/finalized/sync_committees", epoch=str(epoch)).get("data", {})
    if "pubkeys" in d:
        # Algunos clientes entregan las pubkeys directamente
        return d["pubkeys"]
    # Otros entregan solo índices y hay que resolverlos a pubkeys consultando /validators
    indices = d.get("validators") or d.get("validator_indices") or []
    mapping = get_validator_pubkeys(indices, state_id="finalized")
    pubs = [mapping[i] for i in indices if i in mapping]
    if len(pubs) != len(indices):
        missing = len(indices) - len(pubs)
        print(f"Advertencia: faltan {missing} pubkeys al resolver el sync committee")
    return pubs

# ---------------- Bits → participantes ----------------
def decode_bits(bits_hex:str)->list[int]:
    # sync_committee_bits viene como hex. Cada byte se interpreta LSB-first (bit 0 = LSB),
    # siguiendo la convención de la spec para bitfields.
    # Devolvemos una lista de 0/1 de longitud 512 que indica quién firmó.
    h = bits_hex[2:] if bits_hex.startswith("0x") else bits_hex
    bb = bytes.fromhex(h)
    out = []
    for b in bb:
        for i in range(8):        
            out.append((b>>i)&1)   # LSB-first
    # change the last item
    out[-1] = 1 - out[-1]
    return out[:512]

def main():
    print(">> leyendo génesis y fork")
    genesis_root, _ = get_genesis()             # root de validadores de génesis (32B)
    fork_version = get_current_fork_version()   # versión de fork actual del estado finalized (4B)
    DOMAIN_SYNC_COMMITTEE = b"\x07\x00\x00\x00" # domain_type para firmas de sync committee (Altair+)

    print(">> leyendo finality_update")
    u = get_finality_update()                   # trae attested_header + sync_aggregate
    attested_header = u["attested_header"]["beacon"]         # header atestado (objeto con 5 campos del header)
    bits_hex = u["sync_aggregate"]["sync_committee_bits"]      # bitfield de 512 bits (quién firmó)
    sig_hex  = u["sync_aggregate"]["sync_committee_signature"] # firma agregada BLS (G2)

    # Extraemos campos del header (strings hex para roots; enteros para slot/proposer)
    slot, proposer = int(attested_header["slot"]), int(attested_header["proposer_index"])
    parent_root, state_root, body_root = attested_header["parent_root"], attested_header["state_root"], attested_header["body_root"]

    # object_root = HTR(BeaconBlockHeader)
    # Reconstruimos la raíz SSZ del header: esto es lo que "representa" al header en 32 bytes.
    obj_root = beacon_block_header_root(slot, proposer, parent_root, state_root, body_root)

    # domain
    # Construimos el dominio correcto para sync committee:
    # domain = 0x07000000 || compute_fork_data_root(current_version, genesis_root)[:28]
    # Con esto, la firma queda ligada al "tipo sync committee" y a la red/fork adecuada.
    domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_root)

    # signing_root = HTR(SigningData{object_root, domain})
    # Es el "mensaje" que el sync committee firmó (según compute_signing_root de la spec).
    msg = signing_root(obj_root, domain)
    
   
    period = slot // 8192
     # Un período de sync committee dura 8192 slots; el período se obtiene como slot // 8192.
    print(f">> slot={slot}  period={period}")
    committee = get_sync_committee_pubkeys(period)  # 512 hex "0x..." (lista de pubkeys BLS G1)

    # Decodificamos bits y filtramos las pubkeys de quienes realmente firmaron (bits==1).
    bits = decode_bits(bits_hex)

    # participantes = [bytes.fromhex(pk[2:]) for i, pk in enumerate(committee) if i < len(bits) and bits[i]==1]
    participants = [bytes.fromhex(pk[2:]) for i, pk in enumerate(committee) if i < len(bits) and bits[i]==1]
    if not participants:
        # Si no hay participantes "encendidos" no podemos verificar la firma agregada (faltan aportantes)
        print("No hay participantes encendidos en bits; no se puede verificar."); return

    # Parseamos la firma agregada BLS desde hex a bytes (formato G2)
    signature = bytes.fromhex(sig_hex[2:] if sig_hex.startswith("0x") else sig_hex)

    # Métricas informativas: cantidad de bits en 1 vs. cantidad de pubkeys efectivamente resueltas
    print(f">> participantes declarados: {sum(bits)}  usados: {len(participants)}")
    print(">> verificando FastAggregateVerify...")
    # Verificación BLS agregada (BLS12-381): una única firma contra múltiples pubkeys y un mismo mensaje.
    ok = bls.FastAggregateVerify(participants, msg, signature)
    print(">> firma agregada válida? ", ok)

if __name__ == "__main__":
    main()
