package nl.rabobank.jwksdemo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {
    private final JwksService jwksService;

    public JwksController(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    @GetMapping
    public Map<String, Object> keys() {
        return jwksService.getKeySet();
    }
}
