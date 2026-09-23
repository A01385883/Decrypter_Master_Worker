# Decrypter_Master_Worker
### Versión de Ilan



## Metodología:

- El archivo ```master.py``` se encarga de distribuír el trabajo de encriptación entre 'n' cantidad de trabajadores, los cuales ejecutarán el archivo ```worker.py```, que mediante sockets, reciben la tarea y la procesan para devolverla al ```master.py``` una vez terminado.

Argumentos aceptados por: ```master.py```
```bash
# Todos son opcionales
--host IP_ADDR
--port PORT
--num-tasks int   # Cantidad de Tareas a ejecutar.
--num-workers int # Cantidad de WORKERs a esperar.
```

Argumentos aceptados por: ```master.py```
```bash
# Todos son opcionales
--host IP_ADDR # 
--port PORT    # Puerto del host MASTER
```