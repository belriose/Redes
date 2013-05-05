OBJECTS=TP1.pdf

all: TP1.pdf

TP1.pdf: TP1.tex ./*.sty
	pdflatex TP1.tex
	makeindex TP1.tex
	pdflatex TP1.tex
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg

clean:
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg
