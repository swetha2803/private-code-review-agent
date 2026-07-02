import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

class Product {
    private final String id;
    private final String name;
    private final double price;
    private int stock;

    Product(String id, String name, double price, int stock) {
        this.id = id;
        this.name = name;
        this.price = price;
        this.stock = stock;
    }

    String getId() {
        return id;
    }

    String getName() {
        return name;
    }

    double getPrice() {
        return price;
    }

    void reduceStock(int quantity) throws Exception {
        if (stock < quantity) {
            throw new Exception("Insufficient stock");
        }
        stock -= quantity;
    }
}

class Order {
    private final String orderId;
    private final Map<Product, Integer> items = new HashMap<>();

    Order(String orderId) {
        this.orderId = orderId;
    }

    void addItem(Product product, int quantity) {
        items.put(product, quantity);
    }

    Map<Product, Integer> getItems() {
        return items;
    }

    void saveInvoice() {
        String filename = "invoice_" + orderId + ".txt";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            for (Map.Entry<Product, Integer> entry : items.entrySet()) {
                writer.write(entry.getKey().getName() + " " + entry.getValue());
            }
        } catch (IOException e) {
            System.err.println("Failed to write invoice: " + e.getMessage());
        }
    }
}

public class EcommerceApp {
    public static void main(String[] args) {
        Product laptop = new Product("P01", "Laptop", 1200.00, 5);
        Order order = new Order("ORD-1001");
        order.addItem(laptop, 1);
        order.saveInvoice();
    }
}
