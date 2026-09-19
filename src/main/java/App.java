import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Scanner;

/*
 * Aplicación DELIBERADAMENTE VULNERABLE (ejercicio "Implementar SAST On-Premise").
 * Uso exclusivo educativo. Ejecutar solo en una máquina local.
 *
 * Marcas usadas en los comentarios:
 *   [VULN-XX]    -> problema de seguridad (con su CWE y la regla típica de SonarQube)
 *   [CALIDAD-XX] -> problema de calidad / mantenibilidad
 */
public class App {

    // [VULN-01] Credenciales escritas directamente en el código (CWE-798).
    // Cualquiera que vea el repositorio puede leerlas. Deberían venir de
    // variables de entorno o de un gestor de secretos.
    // SonarQube: S2068 (hard-coded credentials).
    private static final String PASSWORD = "admin123";
    private static final String API_KEY = "12345-SECRET-KEY";

    public static void main(String[] args) {

        // [CALIDAD-01] El Scanner solo se cierra al final; si ocurre un error
        // antes, queda abierto. Debería usarse try-with-resources.
        Scanner sc = new Scanner(System.in);

        // [VULN-02] Los datos ingresados por el usuario no se validan ni se
        // limpian (CWE-20). Todo lo que se escribe aquí se usa después en
        // una consulta SQL, en un archivo y en un comando del sistema.
        System.out.print("Ingrese nombre de usuario: ");
        String usuario = sc.nextLine();

        System.out.print("Ingrese nombre de archivo: ");
        String archivo = sc.nextLine();

        // [CALIDAD-02] Captura genérica de Exception: mezcla todos los errores
        // posibles y dificulta saber qué falló. SonarQube: S2221.
        try {

            // [VULN-03] Se conecta a la base de datos con el usuario "root"
            // (máximos privilegios) y con la contraseña escrita en el código
            // (CWE-250 / CWE-798). Debería usarse un usuario con permisos
            // mínimos y credenciales externas.
            // [CALIDAD-03] Connection y Statement no se cierran si ocurre una
            // excepción antes de con.close() (fuga de recursos, CWE-772).
            // Debería usarse try-with-resources. SonarQube: S2095.
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/test",
                    "root",
                    PASSWORD);

            Statement stmt = con.createStatement();

            // [VULN-04] Inyección SQL (CWE-89): la consulta se arma
            // concatenando el texto ingresado por el usuario. Ejemplo de
            // ataque en "usuario":  ' OR '1'='1
            // Corrección: usar PreparedStatement con parámetros (?).
            // SonarQube: S3649.
            String query = "SELECT * FROM usuarios WHERE nombre = '" + usuario + "'";

            // [CALIDAD-04] El resultado (ResultSet) de executeQuery se
            // ignora: se ejecuta la consulta pero nunca se usa ni se cierra.
            stmt.executeQuery(query);

            // [VULN-05] Información sensible expuesta (CWE-200 / CWE-532):
            // se imprimen en pantalla (y posiblemente en logs) la clave de la
            // API y la contraseña. Nunca se deben mostrar secretos.
            System.out.println("API KEY: " + API_KEY);
            System.out.println("Contraseña: " + PASSWORD);

            // [VULN-06] Path Traversal (CWE-22): el nombre del archivo lo
            // controla el usuario y no se valida. Puede escribir
            // ../../etc/passwd para salir de la carpeta prevista. Además se
            // muestra la ruta absoluta (revela la estructura del servidor).
            // Corrección: validar contra una carpeta base y usar
            // file.getCanonicalPath() para comprobar que sigue dentro.
            // SonarQube: S2083.
            File file = new File(archivo);
            System.out.println("Archivo: " + file.getAbsolutePath());

            // [VULN-07] Inyección de comandos del sistema (CWE-78): se
            // construye el comando con texto del usuario. Aunque exec(String)
            // no usa una shell, el usuario puede agregar argumentos extra
            // (por ejemplo "-f") y las herramientas SAST lo marcan como
            // inseguro. Corrección: validar el host con una lista de
            // caracteres permitidos y usar ProcessBuilder con argumentos
            // separados. SonarQube: S2076.
            Runtime.getRuntime().exec("ping " + usuario);

            con.close();

        } catch (Exception e) {

            // [VULN-08] Exposición de información sensible en el manejo de
            // errores (CWE-209 / CWE-497): printStackTrace muestra detalles
            // internos (clases, rutas, datos de conexión). Debería usarse un
            // logger y mostrar al usuario un mensaje genérico.
            // SonarQube: S1148.
            e.printStackTrace();
        }

        sc.close();
    }
}
