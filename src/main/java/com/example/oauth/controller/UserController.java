package com.example.oauth.controller;

import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import com.example.oauth.entity.User;
import com.example.oauth.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Schema(name = "/user", description = "Operations about user")
@Controller
@RequestMapping(value = "/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Operation(summary = "Create user", description = "This can only be done by the logged in user.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Success"),
        @ApiResponse(responseCode = "400", description = "Invalid Request"),
        @ApiResponse(responseCode = "500", description = "Server Error")
    })
    @RequestMapping(method = POST)
    public ResponseEntity<User> createUser(
        @Parameter(name = "user", required = true, schema = @Schema(implementation = User.class))
        @RequestBody User user) {
        userRepository.save(user);
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @Operation(summary = "Updated user", description = "This can only be done by the logged in user.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Success"),
        @ApiResponse(responseCode = "400", description = "Invalid Request"),
        @ApiResponse(responseCode = "500", description = "Server Error")
    })
    @RequestMapping(value = "/{username}", method = PUT)
    public ResponseEntity<String> updateUser(
        @Parameter(name = "name that need to be deleted", required = true)
        @PathVariable("username")
            String username,
        @Parameter(name = "Updated user object", required = true)
        @RequestBody
            User user) {
        if (userRepository.findByUsername(username) != null) {
            userRepository.save(user);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @Operation(summary = "Delete user", description = "This can only be done by the logged in user.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Success"),
        @ApiResponse(responseCode = "400", description = "Invalid Request"),
        @ApiResponse(responseCode = "500", description = "Server Error")
    })
    @RequestMapping(value = "/{username}", method = DELETE)
    public ResponseEntity<String> deleteUser(
        @Parameter(name = "username", description = "The name that needs to be deleted", required = true)
        @PathVariable("username")
            String username) {
        final User user = userRepository.findByUsername(username);

        if (null != user) {
            userRepository.delete(user);
            userRepository.flush();
            return new ResponseEntity<>(HttpStatus.OK);
        }

        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @Operation(summary = "Get user", description = "This can only be done by the logged in user.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Success"),
        @ApiResponse(responseCode = "400", description = "Invalid Request"),
        @ApiResponse(responseCode = "500", description = "Server Error")
    })
    @RequestMapping(value = "/{username}", method = GET)
    public ResponseEntity<User> getUser(
        @Parameter(name = "name that need to be fetched", required = true)
        @PathVariable("username")
            String username) {
        final User user = userRepository.findByUsername(username);

        if (null != user) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }

        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
