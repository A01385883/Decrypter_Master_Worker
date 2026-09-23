# Decrypter_Master_Worker
### Versión de Ilan

**Features:**
- El servidor master puede ser programado para esperar a que **n** cantidad de workers establezcan conexión con él para inicilizar la repartición de tareas.

**Tareas Pendientes (!):**

- Mejorar el algóritmo de Load Balancing para distribución de tasks entre los diferentes workers.

- Implementar un método de reasignación de tareas una vez que uno de los workers se tumbe en la mitad de distribución y ejecución de tareas.

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

