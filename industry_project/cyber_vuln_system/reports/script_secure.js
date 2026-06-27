document.addEventListener("DOMContentLoaded", () => {
    const imageInput = document.getElementById("imageInput");
    const preview = document.getElementById("preview");
    const captionInput = document.getElementById("captionInput");
    const uploadBtn = document.getElementById("uploadBtn");
    const statusEl = document.getElementById("status");

    function selectColour(percentage){
        if(percentage < 70){
            return "reportBad-text"
        }
        else if(percentage >=70 && percentage < 90){
            return "reportOkay-text"
        }
        else{
            return "reportGood-text"
        }
    }

    imageInput.addEventListener("change", () => {
        const file = imageInput.files[0];
        if (file) {
            preview.style.display = "block";
            preview.src = URL.createObjectURL(file);
        } else {
            preview.style.display = "none";
        }
    });

    uploadBtn.addEventListener("click", async () => {
        const imageFile = imageInput.files[0];
        const caption = captionInput.value.trim();

        if (!imageFile || !caption) {
            statusEl.innerText = "Please select an image and enter a caption.";
            return;
        }

        const formData = new FormData();
        formData.append("image", imageFile);
        formData.append("caption", caption);

        statusEl.innerText = "Processing...";

        try {
            const response = await fetch("http://127.0.0.1:5000/upload", {
                method: "POST",
                body: formData
            });

            const body = document.body;

            // If server error →
            if (!response.ok) {
                const errorBox = document.createElement("div");
                errorBox.classList.add("result-container");
                // Sanitize error message before injecting
                const errorMessage = document.createTextNode("Server error. Try again.");
                const errorHeading = document.createElement('h2');
                errorHeading.textContent = 'TrueTrace Result';
                const errorParagraph = document.createElement('p');
                errorParagraph.classList.add('result-text');
                errorParagraph.appendChild(errorMessage);
                errorBox.appendChild(errorHeading);
                errorBox.appendChild(errorParagraph);

                document.querySelector(".container")?.remove();  
                body.appendChild(errorBox);
                return;
            }

            const result = await response.json();

            // Create NEW wider container
            const resultContainer = document.createElement("div");
            resultContainer.classList.add("result-container");

            const heading = document.createElement('h2');
            heading.textContent = 'TrueTrace Result';
            resultContainer.appendChild(heading);

            const submittedTextP = document.createElement('p');
            submittedTextP.classList.add('submitted-text');
            submittedTextP.textContent = caption || "No result found";
            resultContainer.appendChild(submittedTextP);

            const dbCaptionP = document.createElement('p');
            dbCaptionP.classList.add('database-text');
            dbCaptionP.textContent = result.dbCaption || "No result found";
            resultContainer.appendChild(dbCaptionP);

            const reportP = document.createElement('p');
            reportP.classList.add(selectColour(result.similarity));
            reportP.textContent = `We have ${result.similarity ? result.similarity + '%' : 'no'} match!\n${result.report || "No result found"}`;
            resultContainer.appendChild(reportP);

            // Remove old container
            document.querySelector(".container")?.remove();

            // Add new wider container to body
            body.appendChild(resultContainer);

        } catch (err) {
            statusEl.innerText = "An error occurred: " + err.message;
        }
    });
});