# HMAC Bruteforce Solver with Master-Worker Architecture

## Setup Inicial

Para elegir el pcap del cual encontrar la contraseña

*   Guardar paquete RIP en hexadecimal en variable mensaje_rip dentro de función iniciar_master
*   Comentar línea debajo, variable clave_temporal
*   Guardar hash del paquete RIP en la variable debajo, hash_real como str de valores hexadecimales

Para elegir la longitud de la clave

*   En función iniciar_master modificar total_combinaciones, donde el exponente es la cantidad de dígitos de la constraseña

## Para ejecutar

*   Abrir terminal y hacer ipconfig para copiar ipv4
*   Modificar en el código .py el HOST a la ip
*   Abrir terminal en dirección de archivo master
*   Ejecutar: python3 master.py o worker.py
