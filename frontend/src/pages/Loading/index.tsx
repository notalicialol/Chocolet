import styles from "./loading.module.scss";

import { useState, useEffect } from "react";
import { Helmet } from "react-helmet";

import { Background } from "@components/index";

export default function Loading() {
    const [fact, setFact] = useState<string | null>(null);

    const Facts = [
        "The history of chocolate dates back to 1900 BC in Mesoamerica, where the ancient Maya and Aztec civilizations first cultivated the cacao plant.",
        "The Aztecs valued cacao beans so highly that they used them as currency and to pay taxes.",
        "Chocolate was introduced to Europe by the Spanish in the 16th century, initially as a drink.",
        "Milk chocolate was invented by Swiss chocolatier Daniel Peter in 1875, with the help of Henri Nestlé, who provided condensed milk.",
        "\"Cacao\" typically refers to the plant or its beans before processing, while \"cocoa\" usually refers to the processed powder used in chocolate-making.",
        "Dark chocolate is rich in antioxidants and has been linked to a variety of health benefits, including improved heart health and lower blood pressure.",
        "The first solid chocolate bar was made by J.S. Fry & Sons of England in 1847.",
        "Belgium is one of the leading countries in chocolate consumption per capita, alongside Switzerland.",
        "The largest chocolate bar ever made weighed 12,770 kilograms (28,160 pounds) and was created in the UK in 2011.",
        "It takes approximately 400 cacao beans to make one pound (450 grams) of chocolate.",
        "White chocolate isn't technically chocolate as it contains no cocoa solids, only cocoa butter.",
        "The Ivory Coast is the largest producer of cocoa, accounting for approximately 40% of the world's supply.",
        "The smell of chocolate increases theta brain waves, which triggers relaxation.",
        "The scientific name for the tree that chocolate comes from, Theobroma cacao, means \"food of the gods\" in Greek.",
        "Eating dark chocolate every day reduces the risk of heart disease by one-third.",
        "The first chocolate house (comparable to a café) in England opened in London in 1657.",
        "M&M's were created in 1941 as a means for soldiers to enjoy chocolate without it melting.",
        "The world's largest chocolate sculpture, a 10-foot tall Easter egg, weighed 4,484 kg (9,892 lbs).",
        "Chocolate can be lethal to dogs due to the theobromine content, which they cannot metabolize effectively.",
        "A rare fourth type of chocolate, called \"Ruby Chocolate,\" was unveiled in 2017, known for its natural pink color and berry-like flavor."
    ];

    useEffect(() => {
        const index = Math.floor(Math.random() * Facts.length);
        setFact(`Did you know? ${Facts[index]}`);
    }, []);

    return (
        <div className={styles.container}>
            <Helmet defer={false}>
                <title>{import.meta.env.VITE_NAME} | Loading</title>
            </Helmet>
            <Background />
            <img className={styles.loader} src="/logo.png" />
            <div className={styles.loaderText}>Loading content...</div>
            <div className={styles.loaderFact}>{fact}</div>
        </div>
    );
}
