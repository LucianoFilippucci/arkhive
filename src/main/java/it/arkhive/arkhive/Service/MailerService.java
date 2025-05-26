package it.arkhive.arkhive.Service;

import io.mailtrap.client.MailtrapClient;
import io.mailtrap.config.MailtrapConfig;
import io.mailtrap.factory.MailtrapClientFactory;
import io.mailtrap.model.request.emails.Address;
import io.mailtrap.model.request.emails.MailtrapMail;
import it.arkhive.arkhive.Helper.Exceptions.EmailException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class MailerService {

    @Value("${arkhive.mailtrap.token}")
    private String TOKEN;
    @Value("${arkhive.mailtrap.mail-sender}")
    private String SENDER;

    public void sendMail(String subject, String text, String recipient, String username, String url) throws EmailException {
        final MailtrapConfig config = new MailtrapConfig.Builder()
                .token(TOKEN)
                .sandbox(true)
                .inboxId(3726695L)
                .build();

        final MailtrapClient client = MailtrapClientFactory.createMailtrapClient(config);

        final MailtrapMail mail = MailtrapMail.builder()
                .from(new Address(SENDER))
                .to(List.of(new Address(recipient)))
                .templateUuid("fa4b4c50-6e91-4a6c-a353-b1db63a81e94")
                .templateVariables(Map.of(
                        "name", username,
                        "email", recipient,
                        "url", url
                ))
                .build();

        try {
            System.out.println(client.send(mail));
        } catch (Exception e) {
            System.out.println("Cannot send mail: " + e.getMessage());
            throw new EmailException("Cannot Send Email: " + e.getMessage());
        }
    }
}
