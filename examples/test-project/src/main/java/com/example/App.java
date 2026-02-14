package com.example;

/**
 * Example Java application for testing Snyft
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Hello from Snyft test project!");

        UserService userService = new UserService();
        userService.createUser("test@example.com");
    }
}
