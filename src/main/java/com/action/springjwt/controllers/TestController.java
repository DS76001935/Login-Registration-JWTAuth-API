package com.action.springjwt.controllers;

import com.action.springjwt.models.User;
import com.action.springjwt.payload.request.EmailDetails;
import com.action.springjwt.payload.request.UserDTO;
import com.action.springjwt.repository.UserRepository;
import com.action.springjwt.security.jwt.AuthEntryPointJwt;
import com.action.springjwt.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

  private static final Logger log = LoggerFactory.getLogger(TestController.class);

  @Autowired
  private UserService userService;

  @Autowired
  private UserRepository userRepo;

  private static final String DATA = "data";

  @GetMapping("/all")
  public String allAccess() {
    return "Public Content.";
  }

  @GetMapping("/user")
  @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
  public String userAccess() {
    return "User Content.";
  }

  @GetMapping("/mod")
  @PreAuthorize("hasRole('MODERATOR')")
  public String moderatorAccess() {
    return "Moderator Board.";
  }

  @GetMapping("/admin")
  @PreAuthorize("hasRole('ADMIN')")
  public String adminAccess() {
    return "Admin Board.";
  }

  @PostMapping("/changeUserPassword/{newPassword}")
  public String changeUserPassword(@RequestBody UserDTO userModal, @PathVariable String newPassword)
          throws Exception {
    Optional<User> user = userRepo.findByEmail(userModal.getEmail());
    if(user.isPresent()) {
      if (!userService.checkIfValidOldPasswordForUser(user.get(), userModal.getPassword())) {
        return "Invalid Old Password";
      }
      // Save New Password
      userService.changePassword(user.get(), newPassword);
      return "Password Changed Successfully";
    }
    return "!!Invalid User!!";
  }
  @PostMapping("/resetPasswordForUser")
  public ResponseEntity<Map<String,Object>> resetPasswordForUser(@RequestParam("email") String email, HttpServletRequest request)
          throws Exception {

    Map<String, Object> responseMap = new HashMap<>();
    Optional<User> userOp = userRepo.findByEmail(email);
    User user = null;
    if(userOp.isPresent())
      user = userOp.get();
    String url = "";
    if (user != null) {
      String token = UUID.randomUUID().toString();
      userService.createPasswordResetTokenForUser(user, token);
//      url = passwordResetTokenMailForUser(user, processUrl(request), token);
      EmailDetails details = new EmailDetails();
      details.setSubject("Find Reset Password Link Here :--}");
      details.setRecipient(user.getEmail());
      String body = "";
      body +="Respected sir/madam, "+"\r\n" +"You have to verify your account by clicking the below link.";
      body+="\r\n \r\n"+"Instructions: \r\n"+" - This is a token-based user verification which will be longer upto 10 minutes only";
      body += "\r\n - Once you visit the page over this URL, your account should be  thoroughly checked whether valid or not.";
      body+="\r\n - If account is valid or registered in the system, message shown like Account Verified Successfully";
      body += ", After that you can change your password as per your requirement. \r\n";
      body +="Pls visit this url to verify your account => "+guiApplicationUrl(request);
      details.setMsgBody(body);
      String result = userService.sendEmail(details);
      responseMap.put(DATA, token);
      responseMap.put("message","Account verification URL sent to your respective email id");
    }
    return new ResponseEntity<Map<String,Object>>(responseMap, HttpStatus.ACCEPTED);
  }
  @GetMapping("/redirectToResetPage")
  public String redirectToResetPage(@RequestParam("token") String token)
          throws Exception {
    String result = userService.validatePasswordResetToken(token);
    if (!result.equalsIgnoreCase("Verified")) {
      return "!!Invalid Token!!";
    }
    Optional<User> user = userService.getUserByPasswordResetToken(token);

    if (user.isPresent()) {
//      userService.changePassword(user.get(), newPassword);
      return result;
    } else {
      return "!!Invalid Token!!";
    }
  }

  @GetMapping("/getUserFromToken")
  public ResponseEntity<Map<String,Object>> getUserFromToken(@RequestParam("token") String token){
    Map<String, Object> responseMap = new HashMap<>();
    Optional<User> user = userService.getUserByPasswordResetToken(token);
    if(user.isPresent())
        responseMap.put(DATA, user.get());
    else
      responseMap.putIfAbsent(DATA,"No Data");

    return new ResponseEntity<Map<String, Object>>(responseMap,HttpStatus.OK);
  }

  private String passwordResetTokenMailForUser(User user, String applicationUrl, String token) {
    String url = applicationUrl + "/api/test/redirectToResetPage?token=" + token;

    // sendVerificationEmail()
    log.info("Click the link to visit reset-password page: {}"+ user);
    return url;
  }
  private String guiApplicationUrl(HttpServletRequest request) {
    return "http://" + request.getServerName() + ":3000/redirectToResetPage";
  }
//  private String processUrl(HttpServletRequest request) {
//    return "http://" + request.getServerName() + ":"+request.getServerPort()+ request.getContextPath();
//  }
}
