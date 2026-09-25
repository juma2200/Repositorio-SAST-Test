import java.io.File;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/*
 * VERSIÓN CORREGIDA del ejercicio "Implementar SAST On-Premise".
 *
 * Marcas usadas en los comentarios (los números coinciden con la versión
 * vulnerable):
 *   [CORREGIDO VULN-XX]    -> falla de seguridad que se corrigió
 *   [CORREGIDO CALIDAD-XX] -> problema de calidad que se corrigió
 */
public class App {

    // [CORREGIDO CALIDAD-02] Se usa un Logger en vez de imprimir errores
    // directamente en pantalla.
    private static final Logger LOGGER = Logger.getLogger(App.class.getName());

    // [CORREGIDO VULN-01] Se eliminaron PASSWORD y API_KEY del código. Las
    // credenciales de la base de datos se leen desde variables de entorno
    // (DB_USER y DB_PASSWORD).
    private static final String DB_URL = "jdbc:mysql://localhost:3306/test";

    // [CORREGIDO VULN-06] Carpeta base permitida para los archivos.
    private static final Path CARPETA_BASE =
            Paths.get("archivos").toAbsolutePath().normalize();

    // [CORREGIDO VULN-02] Validación de la entrada con lista de caracteres
    // permitidos: letras, números, punto y guion; debe empezar con letra o
    // número (así nunca puede parecer una opción como "-f").
    private static final Pattern PATRON_SEGURO =
            Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]{0,49}$");

    public static void main(String[] args) {

        // [CORREGIDO CALIDAD-01] try-with-resources: el Scanner se cierra
        // siempre, aunque ocurra un error.
        try (Scanner sc = new Scanner(System.in)) {

            System.out.print("Ingrese nombre de usuario: ");
            String usuario = sc.nextLine();

            System.out.print("Ingrese nombre de archivo: ");
            String archivo = sc.nextLine();

            // [CORREGIDO VULN-02] Si el usuario no cumple el formato, no se
            // continúa.
            if (!PATRON_SEGURO.matcher(usuario).matches()) {
                System.out.println("Nombre de usuario inválido.");
                return;
            }

            consultarUsuario(usuario);
            mostrarArchivo(archivo);
            hacerPing(usuario);
        }
    }

    private static void consultarUsuario(String usuario) {

        // [CORREGIDO VULN-01 / VULN-03] Credenciales desde el entorno. Se
        // recomienda usar un usuario de base de datos con permisos mínimos
        // (solo SELECT sobre "usuarios"), no "root".
        String dbUser = System.getenv("DB_USER");
        String dbPassword = System.getenv("DB_PASSWORD");
        if (dbUser == null || dbPassword == null) {
            LOGGER.severe("Faltan las variables de entorno DB_USER y DB_PASSWORD.");
            return;
        }

        // [CORREGIDO VULN-04] Consulta parametrizada (PreparedStatement): el
        // dato del usuario nunca se mezcla con el texto SQL.
        String query = "SELECT * FROM usuarios WHERE nombre = ?";

        // [CORREGIDO CALIDAD-03] Connection, PreparedStatement y ResultSet se
        // cierran automáticamente con try-with-resources.
        try (Connection con = DriverManager.getConnection(DB_URL, dbUser, dbPassword);
             PreparedStatement ps = con.prepareStatement(query)) {

            ps.setString(1, usuario);

            // [CORREGIDO CALIDAD-04] Ahora el resultado sí se usa y se cierra.
            try (ResultSet rs = ps.executeQuery()) {
                System.out.println(rs.next()
                        ? "Usuario encontrado."
                        : "Usuario no encontrado.");
            }

            // [CORREGIDO VULN-05] Ya no se imprimen la API key ni la
            // contraseña.

        } catch (SQLException e) {
            // [CORREGIDO CALIDAD-02 / VULN-08] Se captura la excepción
            // específica (SQLException). El detalle técnico va al logger
            // (en producción, a un archivo protegido) y al usuario solo se
            // le muestra un mensaje genérico.
            LOGGER.log(Level.SEVERE, "Error al consultar la base de datos", e);
            System.out.println("No se pudo completar la consulta.");
        }
    }

    private static void mostrarArchivo(String archivo) {
        try {
            // [CORREGIDO VULN-06] Path Traversal: la ruta se resuelve dentro
            // de la carpeta base y se normaliza (elimina "../"). Si el
            // resultado queda fuera de la carpeta base (incluye rutas
            // absolutas como /etc/passwd), se rechaza.
            Path ruta = CARPETA_BASE.resolve(archivo).normalize();
            if (!ruta.startsWith(CARPETA_BASE)) {
                System.out.println("Ruta de archivo no permitida.");
                return;
            }

            File file = ruta.toFile();

            // [CORREGIDO VULN-06] Solo se muestra el nombre, no la ruta
            // absoluta (no se revela la estructura del servidor).
            System.out.println("Archivo: " + file.getName());

        } catch (InvalidPathException e) {
            System.out.println("Nombre de archivo inválido.");
        }
    }

    private static void hacerPing(String host) {

        // [CORREGIDO VULN-07] Se usa ProcessBuilder con cada argumento por
        // separado (no se arma un texto de comando) y el host ya fue
        // validado con PATRON_SEGURO. Se usa "-n" en Windows y "-c" en el
        // resto de sistemas.
        String opcion = System.getProperty("os.name").toLowerCase().contains("win")
                ? "-n" : "-c";
        ProcessBuilder pb = new ProcessBuilder("ping", opcion, "1", host);
        pb.inheritIO();

        try {
            Process proceso = pb.start();

            // Tiempo máximo de espera para que no se quede colgado.
            if (!proceso.waitFor(5, TimeUnit.SECONDS)) {
                proceso.destroyForcibly();
                System.out.println("El ping tardó demasiado y se canceló.");
            }

        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "No se pudo ejecutar el comando ping", e);
            System.out.println("No se pudo ejecutar ping.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Operación interrumpida.");
        }
    }
}
