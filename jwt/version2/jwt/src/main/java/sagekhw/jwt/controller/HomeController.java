package sagekhw.jwt.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/home")
public class HomeController {

    @PostMapping("/user")
    @PreAuthorize("hasAnyRole('USER')")
    public String test1(){
        return "USER";
    }
    @PostMapping("/admin")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public String test2(){
        return "ADMIN";
    }
}
