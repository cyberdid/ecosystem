# Skills — portable payloads, not automatic trust

Кожна навичка: `skills/<name>/SKILL.md` (frontmatter: `name`, `description`) + опц. `scripts/`, `references/`.

- Skill payload пишеться один раз; client-specific installation є adapter operation, не доказ semantic portability.
- Урок після реального фейлу дописується у відповідний SKILL.md (процедурна пам'ять, їде між проєктами).
- Skill не отримує permissions із власного description/frontmatter.
- До promotion потрібні source, version, immutable digest, license, requested capabilities, provenance/signature status, scan та behavioral evaluation.
- Revocation/quarantine важливі не менше за initial install.
- Джерела аудитуються до встановлення; scripts і references вважаються untrusted supply-chain artifacts.

Черга на evaluation, не автоматичне перенесення: `dgx_spark` inference/ml/platform skills, wiki-health-check і вже встановлені external skills. Canonical lock format буде додано після skill schema.
