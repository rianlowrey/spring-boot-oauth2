package com.example.oauth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.Serializable;
import java.util.Collections;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name = "users", schema = "public", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"username"})
})
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @NotBlank
    @Column(name = "username", length = 50, nullable = false)
    private String username;

    @NotBlank
    @Column(name = "password", length = 256, nullable = false)
    private String password;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @OneToMany(mappedBy = "compositeKey.username", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private Set<Authority> authorities = Collections.emptySet();

    public String getUsername() {
        return this.username;
    }

    @JsonIgnore
    public String getPassword() {
        return this.password;
    }

    public Set<Authority> getAuthorities() {
        return this.authorities;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }
}
