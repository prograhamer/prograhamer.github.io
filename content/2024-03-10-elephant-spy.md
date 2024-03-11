+++
title = "My First Post^H^H^H^HBrowser Extension"
date = "2024-03-10"
+++

Recently, I have played quite a lot of Ark Nova with friends on [boardgamearena.com](https://boardgamearena.com). For anyone who hasn't played it, it's a card-based zoo management game with a lot of replayability. There are a few random elements to the game setup and you need to tailor your strategy to the situation.

Through all the variation in our games, there have been a few key animals that always seem very powerful, no matter the game situation. Animals typically have a special ability, or effect, when played, and some of these effects can have a major impact on the game outcome. For example, there are elephants, which allow you to draw an additional final scoring card, which can lead to a dramatic swing in the scoring at the end of the game.

Now, I wanted to be more aware of when one of these animals was played. To that end, I had the thought that I could write a browser extension that monitors the DOM for elements that are rendered when one of these animals is played.

The full source for what is described below is available on [my GitHub](https://github.com/prograhamer/elephant-spy).

## Elephant Spy is Born

My original idea was just concerned with elephants, with the reasoning already stated above. I thought it would be entertaining to have the sound of an elephant tooting as an alert any time an elephant card is played.

Trouble is, I had no idea how to write a browser extension, but I figured (hoped?) it would probably just be plain old JavaScript. MDN has a really nice documentation on [writing browser extensions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions), that gave me a solid place to start.

It seemed that I would just need a `manifest.json` and some simple JavaScript to get something working. What I wanted to achieve was so simple that almost everything is covered in the "your first extension" [example](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Your_first_WebExtension). Aside from the metadata describing the plugin, setting an icon, etc., all I needed was a `content_scripts` section to match `boardgamearena.com` and provide a script to inject into that site.

```json
"content_scripts": [
  {
    "matches": ["*://*.boardgamearena.com/*"],
    "js": ["elephant.js"]
  }
],
```

To start with, my `elephant.js` didn't do anything around monitoring the DOM for changes and just tweaked a CSS property with the `!important` modifier to demonstrate to myself that the extension was actually loading and running.

After that I decided to test out playing sounds in the browser. For this I just needed the `browser.runtime.getURL()` function to get a fully qualified URL for the audio assets bundled in the extension. As demonstrated in the, "your second extension" [example](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Your_second_WebExtension) on MDN.

## Watching for Elephants

I had two problems when it came to actually writing the functionality of the extension:
- How to monitor the DOM for changes and see that the appropriate element was rendered
- How to match the animal cards I'm interested in

### Observing DOM Mutations

The first problem can be solved with the `MutationObserver` API ([MDN](https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver)). This API gives a nice way to watch the DOM and get a callback to a function when cetain events occur. In my case, I'm interested in seeing when a new DOM node representing an elephant card is added. This can be achieved by specifying the option `childList: true` when creating the mutation observer, to monitor additions and deletions of nodes. Setting `subtree: true` specifies that those additions and deletions can happen anywhere in the subtree being watched, since we do not know exactly where the card will be rendered.

Putting all that together, we get the following:
```js,linenos
const logger = (records, observer) => {
  for (const record of records) {
    for (const added of record.addedNodes) {
      console.log("node added");
    }
  }
};

const observer = new MutationObserver(logger);
const target = document.querySelector("body");
observer.observe(target, {
  childList: true,
  subtree: true,
});
```

- Lines 1-7 create a callback back function that will log any DOM node addition
- Line 9 creates a new `MutationObserver` with our callback
- Line 10 selects the `body` element as the target for the observer
- Lines 11-14 start the observer, with the options `childList: true` and `subtree: true` as discussed above

### Identifying Elephants

The next question is how to identify elephants. Looking at animal cards in the game, the top-level element appears to be a `div` with classes `ark-card` and `animal-card` and an `id` attribute something like `card-A452_SenegalBushbaby`. The first approach I went with was the following, just watching for any added nodes whose `id` attribute matches the regex `/[Ee]lephant/`:

```js
const callback = (records, observer) => {
  for (const record of records) {
    for (const added of record.addedNodes) {
      if (added.id && /[Ee]lephant/.test(added.id)) {
        trumpeter.play();
      }
    }
  }
};
```

Where `trumpeter` is an `audio` element the extension adds to the body of the page. This basic version worked for me and I was warned of any elephant action with a mighty toot! Exciting times.

## Eagles and Rhinos

It's not just elephants that are interesting animals to see appear in the game! Eagles are also very powerful, giving the player an extra turn when they are played, which can be huge in the final round.

In order to add support for these animals, I needed to rethink some things about how the matching might work, in order to support more animal types. Side note: I also needed to find representative sounds for the animals for the alerts, and this in itself was probably one of the most fun parts of the project!

The ability elephants have is called "resistance" in game, and the eagles have "determination". I decided that I should match on the ability name, rather than the animal name, given that is what I was really interested in - it seemed more direct. The only unfortunate side-effect of this is that some snakes would now sound like eagles, when playing in a particular game mode where they have the same ability as the eagles, but I'd rather have a snake sound like a bird, than miss that a key card was played. Maybe one day I'll go back to matching on the animal names, and have a special case for the couple of snakes that behave differently in that game mode, so they sound less strange.

Rhinos are also interesting, giving the player the ability to take a conservation project card of their choosing, which again can lead to a big swing in points, depending on the game situation.

In order to support both rhinos and eagles, I switched to matching the top-level card element, using its classes of `ark-card` and `animal-card`. Then I created an array of alerts, each containing a regex to match the card element's `innerText` on, and the appropriate audio element to play if a match is found. With that in place, I can simply iterate over the array, testing the regex for each and playing its alert sound if the regex matches, something like:

```js
const callback = (records, observer) => {
  for (const record of records) {
    for (const added of record.addedNodes) {
      if (added.classList &&
          added.classList.contains("ark-card") &&
          added.classList.contains("animal-card")) {
        for (alert of alerts) {
          if (alert.re.test(added.innerText)) {
            alert.audio.play()
          }
        }
      }
    }
  }
};
```

## Supporting Chrome

While I originally only cared about supporting my own usage of the extension in Firefox, at least one of my friends expressed interest in using it in Chrome. In this extension, the only things I had to change were:
- Use a PNG icon, not an SVG. I had originally made an SVG I was pretty pleased with that supported both light and dark mode UI in Firefox. It turns out Chrome doesn't support SVG extension icons. Boo.
- Use `chrome.runtime` instead of `browser.runtime`

Again, [MDN](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Chrome_incompatibilities) has a good page describing some of the incompatibilities between Chrome and Firefox extensions, and how to address them.
