# Verificación de Cabeceras de Beacon Chain

Este proyecto contiene un script en Python (`verificacion.py`) diseñado para interactuar con un nodo de la Beacon Chain de Ethereum y verificar la autenticidad de las actualizaciones de finalidad (*Finality Updates*) utilizando firmas BLS y serialización SSZ.

## Descripción

El script realiza las siguientes funciones principales:

1.  **Conexión a la Beacon API**: Se conecta a un nodo de consenso (por defecto en `http://127.0.0.1:5052`) para obtener datos de génesis, versión del fork y actualizaciones de finalidad.
2.  **Cálculo de Raíces SSZ**: Implementa funciones para calcular el *HashTreeRoot* de estructuras de datos como `BeaconBlockHeader`, `ForkData` y `SigningData` siguiendo la especificación de Simple Serialize (SSZ).
3.  **Obtención de Claves Públicas**: Recupera las claves públicas de los validadores del *Sync Committee* activo para el periodo actual.
4.  **Verificación de Firmas BLS**: Utiliza la librería `py_ecc` para realizar una `FastAggregateVerify`. Esto comprueba que la firma agregada recibida en el `FinalityUpdate` corresponde efectivamente a los validadores del comité que indicaron su participación (a través de los `sync_committee_bits`).

## Requisitos Previos

*   **Python 3.x**: Asegúrate de tener Python 3 instalado.
*   **Nodo Beacon**: Necesitas acceso a un nodo de la Beacon Chain de Ethereum (como Lighthouse, Prysm, Teku, etc.) que tenga habilitada la API REST. Por defecto, el script busca el nodo en `http://127.0.0.1:5052`.

## Instalación

1.  Clona este repositorio o descarga los archivos.
2.  Instala las dependencias necesarias utilizando `pip` y el archivo `requirements.txt`:

```bash
pip install -r requirements.txt
```

Las dependencias principales son:
*   `requests`: Para realizar peticiones HTTP a la API del nodo.
*   `py_ecc`: Para las operaciones criptográficas de curvas elípticas (BLS12-381).

## Uso

Para ejecutar el script de verificación, simplemente corre el siguiente comando en tu terminal:

```bash
python3 verificacion.py
```

### Flujo de Ejecución

Al ejecutar el script, verás una salida similar a esta:

1.  `>> leyendo génesis y fork`: Obtiene información básica de la red.
2.  `>> leyendo finality_update`: Descarga la última actualización de finalidad.
3.  `>> slot=... period=...`: Muestra el slot y el periodo del comité de sincronización.
4.  `>> participantes declarados: ... usados: ...`: Indica cuántos validadores firmaron.
5.  `>> verificando FastAggregateVerify...`: Realiza la verificación criptográfica.
6.  `>> firma agregada válida? True`: Confirma si la firma es válida.

## Configuración

Si tu nodo Beacon se encuentra en una dirección diferente a `http://127.0.0.1:5052`, puedes modificar la variable `BEACON` al inicio del archivo `verificacion.py`:

```python
BEACON = "http://TU_DIRECCION_IP:PUERTO"
```

## Conceptos Clave

*   **SSZ (Simple Serialize)**: El método de serialización estándar utilizado en la capa de consenso de Ethereum.
*   **BLS Signatures**: Esquema de firma digital que permite la agregación de firmas, fundamental para la escalabilidad de Ethereum.
*   **Sync Committee**: Un grupo de 512 validadores elegidos cada 256 epochs para firmar las cabeceras de los bloques, permitiendo a los clientes ligeros verificar la cadena con baja sobrecarga.
