import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Scanner;

public class App {

    // Contraseña hardcodeada (vulnerabilidad)
    private static final String PASSWORD = "admin123";

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        System.out.print("Ingrese nombre de usuario: ");
        String usuario = sc.nextLine();

        try {
            // Credenciales hardcodeadas
            Connection con = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/test",
                    "root",
                    PASSWORD);

            Statement stmt = con.createStatement();

            // SQL Injection
            String query = "SELECT * FROM usuarios WHERE nombre = '" + usuario + "'";

            System.out.println("Ejecutando: " + query);

            stmt.executeQuery(query);

            // Información sensible expuesta
            System.out.println("Conectado con contraseña: " + PASSWORD);

            con.close();

        } catch (Exception e) {

            // Stack trace expuesto
            e.printStackTrace();
        }

        sc.close();
    }
}
