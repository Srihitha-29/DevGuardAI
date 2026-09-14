public class TestSQL {

    public void getUser(int id) {

        String query = "SELECT * FROM users WHERE id=" + id;

        System.out.println(query);
    }
}