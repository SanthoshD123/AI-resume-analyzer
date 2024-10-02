import re
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
import PyPDF2
import os
from datetime import datetime


class AdvancedResumeAnalyzer:
    def __init__(self):
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)

        self.stop_words = set(stopwords.words('english'))

        # Refined technical skills dictionary with more detailed categories
        self.technical_skills = {
            'programming_languages': {
                'python': 8, 'java': 8, 'javascript': 7, 'c++': 7, 'ruby': 6, 'php': 6,
                'scala': 6, 'r': 6, 'golang': 7, 'swift': 6, 'python (basics)': 5
            },
            'cybersecurity': {
                'ethical hacking': 9, 'cyber security': 9, 'penetration testing': 9,
                'network security': 8, 'security analysis': 8, 'vulnerability assessment': 8,
                'incident response': 8, 'security tools': 7, 'cryptography': 7,
                'firewall': 7, 'intrusion detection': 8, 'malware analysis': 8
            },
            'operating_systems': {
                'linux': 8, 'windows': 7, 'macos': 6, 'unix': 7, 'linux os': 7,
                'kali linux': 8, 'ubuntu': 7, 'red hat': 7
            },
            'networking': {
                'tcp/ip': 8, 'dns': 7, 'dhcp': 7, 'vpn': 8, 'routing': 7,
                'switching': 7, 'firewall configuration': 8, 'network protocols': 8,
                'computer networks': 7
            },
            'certifications': {
                'cissp': 9, 'ceh': 9, 'security+': 8, 'network+': 7, 'oscp': 9,
                'comptia': 7, 'palo alto': 8
            }
        }

        # Updated section weights
        self.section_weights = {
            'skills': 0.3,
            'education': 0.25,
            'projects': 0.2,
            'experience': 0.25
        }

    def extract_text(self, pdf_path):
        try:
            with open(pdf_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                text = ""
                for page in reader.pages:
                    text += page.extract_text()
            return text
        except Exception as e:
            print(f"Error extracting text from PDF: {str(e)}")
            return ""

    def calculate_experience(self, text):
        try:
            current_year = datetime.now().year
            years = re.findall(r'\b20\d{2}\b', text)
            if years:
                years = [int(year) for year in years]
                return current_year - min(years)
            return 0
        except Exception:
            return 0

    def extract_contact_info(self, text):
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        phone_pattern = r'\+?\d{2,3}[-\s]?\d{5}[-\s]?\d{5}'
        linkedin_pattern = r'linkedin\.com/in/[\w-]+'
        github_pattern = r'github\.com/[\w-]+'

        return {
            'email': next(iter(re.findall(email_pattern, text)), None),
            'phone': next(iter(re.findall(phone_pattern, text)), None),
            'linkedin': next(iter(re.findall(linkedin_pattern, text.lower())), None),
            'github': next(iter(re.findall(github_pattern, text.lower())), None)
        }

    def extract_education(self, text):
        education = []
        # Modified regex to handle both dates and degrees more accurately
        education_pattern = r'(\b(?:MCA|BSc|Bachelor|Master|PhD)\b.*?\d{4}\s*-\s*\d{4})'
        matches = re.findall(education_pattern, text, re.DOTALL)

        for match in matches:
            score = self._score_education(match)
            education.append({
                'details': match.strip(),
                'score': score
            })

        return education

    def _score_education(self, edu_text):
        score = 0
        edu_text = edu_text.lower()
        if 'phd' in edu_text or 'doctorate' in edu_text:
            score = 100
        elif 'master' in edu_text or 'mca' in edu_text:
            score = 90
        elif 'bachelor' in edu_text or 'bsc' in edu_text:
            score = 80

        cgpa_match = re.search(r'cgpa\s*(\d+\.?\d*)', edu_text)
        if cgpa_match:
            cgpa = float(cgpa_match.group(1))
            if cgpa >= 8.5:
                score += 10
            elif cgpa >= 8.0:
                score += 8
            elif cgpa >= 7.5:
                score += 5

        return score

    def extract_skills(self, text):
        found_skills = {category: [] for category in self.technical_skills}
        skill_scores = {category: 0 for category in self.technical_skills}
        text_lower = text.lower()

        for category, skills in self.technical_skills.items():
            for skill, relevance in skills.items():
                if skill in text_lower:
                    found_skills[category].append(skill)
                    skill_scores[category] += relevance

        return {
            'found_skills': found_skills,
            'skill_scores': skill_scores
        }

    def extract_projects(self, text):
        projects = []
        project_pattern = r'Project Title.*?(?=\n\n|\Z)'
        matches = re.findall(project_pattern, text, re.DOTALL | re.IGNORECASE)

        for match in matches:
            score = self._score_project(match)
            projects.append({
                'details': match.strip(),
                'score': score
            })

        return projects

    def _score_project(self, project_text):
        score = 60
        project_text = project_text.lower()

        cybersecurity_keywords = ['security', 'cyber', 'hack', 'vulnerabil', 'threat', 'attack', 'defense']
        for keyword in cybersecurity_keywords:
            if keyword in project_text:
                score += 5

        technical_keywords = ['developed', 'implemented', 'designed', 'architected', 'optimized']
        for keyword in technical_keywords:
            if keyword in project_text:
                score += 3

        return min(score, 100)

    def calculate_overall_score(self, analysis):
        scores = {}

        # Calculate skills score
        if analysis.get('skills', {}).get('skill_scores'):
            skill_scores = analysis['skills']['skill_scores'].values()
            scores['skills'] = sum(skill_scores) / max(len(skill_scores), 1)

        # Calculate education score
        if analysis.get('education'):
            edu_scores = [edu['score'] for edu in analysis['education']]
            scores['education'] = sum(edu_scores) / max(len(edu_scores), 1)

        # Calculate projects score
        if analysis.get('projects'):
            project_scores = [proj['score'] for proj in analysis['projects']]
            scores['projects'] = sum(project_scores) / max(len(project_scores), 1)

        # Calculate experience score
        scores['experience'] = min(analysis['years_of_experience'], 10) * 10

        # Calculate weighted score
        total_weight = sum(self.section_weights[category] for category in scores.keys())
        if total_weight == 0:
            return 0

        weighted_score = sum(scores.get(category, 0) * self.section_weights.get(category, 0)
                             for category in self.section_weights.keys())

        normalized_score = weighted_score / total_weight
        return round(normalized_score, 2)

    def analyze_resume(self, pdf_path):
        if not pdf_path.lower().endswith('.pdf'):
            print("Error: Please provide a PDF file.")
            return None

        text = self.extract_text(pdf_path)
        if not text:
            return None

        skills_data = self.extract_skills(text)
        education_data = self.extract_education(text)
        projects_data = self.extract_projects(text)

        analysis = {
            'contact_info': self.extract_contact_info(text),
            'education': education_data,
            'skills': {
                'found_skills': skills_data['found_skills'],
                'skill_scores': skills_data['skill_scores']
            },
            'projects': projects_data,
            'years_of_experience': self.calculate_experience(text)
        }

        analysis['overall_score'] = self.calculate_overall_score(analysis)

        return analysis


def format_output(analysis):
    output = "\n=== Resume Analysis Results ===\n"

    output += f"\n--- Overall Score: {analysis['overall_score']}/100 ---\n"

    output += "\n--- Contact Information ---\n"
    for key, value in analysis['contact_info'].items():
        if value:
            output += f"{key.capitalize()}: {value}\n"

    output += f"\n--- Experience ---\nYears of Experience: {analysis['years_of_experience']}\n"

    if analysis.get('education'):
        output += "\n--- Education ---\n"
        for edu in analysis['education']:
            output += f"• {edu['details']} (Score: {edu['score']})\n"

    if analysis.get('skills', {}).get('found_skills'):
        output += "\n--- Skills ---\n"
        for category, skills in analysis['skills']['found_skills'].items():
            if skills:
                category_score = analysis['skills']['skill_scores'][category]
                output += f"{category.replace('_', ' ').title()} (Score: {category_score}):\n"
                output += f"  {', '.join(skills)}\n"

    if analysis.get('projects'):
        output += "\n--- Projects ---\n"
        for project in analysis['projects']:
            output += f"• {project['details']} (Score: {project['score']})\n"

    return output


def main():
    analyzer = AdvancedResumeAnalyzer()

    try:
        resume_path = r'your file path'
        print(f"Analyzing resume: {resume_path}")

        analysis = analyzer.analyze_resume(resume_path)

        if analysis:
            print(format_output(analysis))
        else:
            print("Failed to analyze the resume. Please check the file and try again.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
