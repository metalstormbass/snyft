package com.example;

import java.util.ArrayList;
import java.util.List;

/**
 * User service for managing users
 */
public class UserService {
    private List<String> users;

    public UserService() {
        this.users = new ArrayList<>();
    }

    public void createUser(String email) {
        users.add(email);
        System.out.println("User created: " + email);
    }

    public List<String> getAllUsers() {
        return new ArrayList<>(users);
    }

    public int getUserCount() {
        return users.size();
    }
}
