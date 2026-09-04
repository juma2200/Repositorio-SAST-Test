import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Scanner;

public class App {

    private static final String PASSWORD = "admin123";
    private static final String API_KEY = "12345-SECRET-KEY";

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.print("Ingrese nombre de usuario: ");
        String usuario = sc.nextLine();

        System.out.print("Ingrese nombre de archivo: ");
        String archivo = sc.nextLine();

        try {

            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/test",
                    "root",
                    PASSWORD);

            Statement stmt = con.createStatement();

            // SQL Injection
            String query = "SELECT * FROM usuarios WHERE nombre = '" + usuario + "'";
            stmt.executeQuery(query);

            // Información sensible expuesta
            System.out.println("API KEY: " + API_KEY);
            System.out.println("Contraseña: " + PASSWORD);

            // Path Traversal
            File file = new File(archivo);
            System.out.println("Archivo: " + file.getAbsolutePath());

            // Comando del sistema inseguro
            Runtime.getRuntime().exec("ping " + usuario);

            con.close();

        } catch (Exception e) {

            // Exposición de información sensible
            e.printStackTrace();
        }

        sc.close();
    }
}
