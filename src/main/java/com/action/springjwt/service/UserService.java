package com.action.springjwt.service;

import com.action.springjwt.models.User;
import com.action.springjwt.payload.request.EmailDetails;

import java.util.Optional;

public interface UserService {

    Boolean checkIfValidOldPasswordForUser(User user, String password);
    void changePassword(User user, String newPassword);

    void createPasswordResetTokenForUser(User user, String token);

    Optional<User> getUserByPasswordResetToken(String token);

    String validatePasswordResetToken(String token);

    String sendEmail(EmailDetails details);
}
